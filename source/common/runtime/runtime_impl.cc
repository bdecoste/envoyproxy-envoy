#include "common/runtime/runtime_impl.h"

#include <cstdint>
#include <random>
#include <string>
#include <unordered_map>

#include "envoy/event/dispatcher.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/type/percent.pb.validate.h"

#include "common/common/assert.h"
#include "common/common/fmt.h"
#include "common/common/utility.h"
#include "common/filesystem/directory.h"
#include "common/filesystem/filesystem_impl.h"
#include "common/protobuf/utility.h"

namespace Envoy {
namespace Runtime {

bool SnapshotImpl::featureEnabled(const std::string& key, uint64_t default_value,
                                  uint64_t random_value, uint64_t num_buckets) const {
  return random_value % num_buckets < std::min(getInteger(key, default_value), num_buckets);
}

bool SnapshotImpl::featureEnabled(const std::string& key, uint64_t default_value) const {
  // Avoid PNRG if we know we don't need it.
  uint64_t cutoff = std::min(getInteger(key, default_value), static_cast<uint64_t>(100));
  if (cutoff == 0) {
    return false;
  } else if (cutoff == 100) {
    return true;
  } else {
    return generator_.random() % 100 < cutoff;
  }
}

bool SnapshotImpl::featureEnabled(const std::string& key, uint64_t default_value,
                                  uint64_t random_value) const {
  return featureEnabled(key, default_value, random_value, 100);
}

const std::string& SnapshotImpl::get(const std::string& key) const {
  auto entry = values_.find(key);
  if (entry == values_.end()) {
    return EMPTY_STRING;
  } else {
    return entry->second.raw_string_value_;
  }
}

bool SnapshotImpl::featureEnabled(const std::string& key,
                                  const envoy::type::FractionalPercent& default_value) const {
  return featureEnabled(key, default_value, generator_.random());
}

bool SnapshotImpl::featureEnabled(const std::string& key,
                                  const envoy::type::FractionalPercent& default_value,
                                  uint64_t random_value) const {
  const auto& entry = values_.find(key);
  uint64_t numerator, denominator;
  if (entry != values_.end() && entry->second.fractional_percent_value_.has_value()) {
    numerator = entry->second.fractional_percent_value_->numerator();
    denominator = ProtobufPercentHelper::fractionalPercentDenominatorToInt(
        entry->second.fractional_percent_value_->denominator());
  } else if (entry != values_.end() && entry->second.uint_value_.has_value()) {
    // The runtime value must have been specified as an integer rather than a fractional percent
    // proto. To preserve legacy semantics, we'll assume this represents a percentage.
    numerator = entry->second.uint_value_.value();
    denominator = 100;
  } else {
    numerator = default_value.numerator();
    denominator =
        ProtobufPercentHelper::fractionalPercentDenominatorToInt(default_value.denominator());
  }

  return random_value % denominator < numerator;
}

uint64_t SnapshotImpl::getInteger(const std::string& key, uint64_t default_value) const {
  auto entry = values_.find(key);
  if (entry == values_.end() || !entry->second.uint_value_) {
    return default_value;
  } else {
    return entry->second.uint_value_.value();
  }
}

const std::vector<Snapshot::OverrideLayerConstPtr>& SnapshotImpl::getLayers() const {
  return layers_;
}

SnapshotImpl::SnapshotImpl(RandomGenerator& generator, RuntimeStats& stats,
                           std::vector<OverrideLayerConstPtr>&& layers)
    : layers_{std::move(layers)}, generator_{generator} {
  for (const auto& layer : layers_) {
    for (const auto& kv : layer->values()) {
      values_.erase(kv.first);
      values_.emplace(kv.first, kv.second);
    }
  }
  stats.num_keys_.set(values_.size());
}

SnapshotImpl::Entry SnapshotImpl::createEntry(const std::string& value) {
  Entry entry;
  entry.raw_string_value_ = value;

  // As a perf optimization, attempt to parse the entry's string and store it inside the struct. If
  // we don't succeed that's fine.
  resolveEntryType(entry);

  return entry;
}

bool SnapshotImpl::parseEntryUintValue(Entry& entry) {
  uint64_t converted_uint64;
  if (StringUtil::atoul(entry.raw_string_value_.c_str(), converted_uint64)) {
    entry.uint_value_ = converted_uint64;
    return true;
  }
  return false;
}

void SnapshotImpl::parseEntryFractionalPercentValue(Entry& entry) {
  envoy::type::FractionalPercent converted_fractional_percent;
  try {
    MessageUtil::loadFromYamlAndValidate(entry.raw_string_value_, converted_fractional_percent);
  } catch (const ProtoValidationException& ex) {
    ENVOY_LOG(error, "unable to validate fraction percent runtime proto: {}", ex.what());
    return;
  } catch (const EnvoyException& ex) {
    // An EnvoyException is thrown when we try to parse a bogus string as a protobuf. This is fine,
    // since there was no expectation that the raw string was a valid proto.
    return;
  }

  entry.fractional_percent_value_ = converted_fractional_percent;
}

void AdminLayer::mergeValues(const std::unordered_map<std::string, std::string>& values) {
  for (const auto& kv : values) {
    values_.erase(kv.first);
    if (!kv.second.empty()) {
      values_.emplace(kv.first, SnapshotImpl::createEntry(kv.second));
    }
  }
  stats_.admin_overrides_active_.set(values_.empty() ? 0 : 1);
}

DiskLayer::DiskLayer(const std::string& name, const std::string& path) : OverrideLayerImpl{name} {
  walkDirectory(path, "", 1);
}

void DiskLayer::walkDirectory(const std::string& path, const std::string& prefix, uint32_t depth) {
  ENVOY_LOG(debug, "walking directory: {}", path);
  if (depth > MaxWalkDepth) {
    throw EnvoyException(fmt::format("Walk recursion depth exceded {}", MaxWalkDepth));
  }
  // Check if this is an obviously bad path.
  if (Filesystem::illegalPath(path)) {
    throw EnvoyException(fmt::format("Invalid path: {}", path));
  }

  Filesystem::Directory directory(path);
  for (const Filesystem::DirectoryEntry& entry : directory) {
    std::string full_path = path + "/" + entry.name_;
    std::string full_prefix;
    if (prefix.empty()) {
      full_prefix = entry.name_;
    } else {
      full_prefix = prefix + "." + entry.name_;
    }

    if (entry.type_ == Filesystem::FileType::Directory && entry.name_ != "." &&
        entry.name_ != "..") {
      walkDirectory(full_path, full_prefix, depth + 1);
    } else if (entry.type_ == Filesystem::FileType::Regular) {
      // Suck the file into a string. This is not very efficient but it should be good enough
      // for small files. Also, as noted elsewhere, none of this is non-blocking which could
      // theoretically lead to issues.
      ENVOY_LOG(debug, "reading file: {}", full_path);
      std::string value;

      // Read the file and remove any comments. A comment is a line starting with a '#' character.
      // Comments are useful for placeholder files with no value.
      const std::string text_file{Filesystem::fileReadToEnd(full_path)};
      const auto lines = StringUtil::splitToken(text_file, "\n");
      for (const auto line : lines) {
        if (!line.empty() && line.front() == '#') {
          continue;
        }
        if (line == lines.back()) {
          const absl::string_view trimmed = StringUtil::rtrim(line);
          value.append(trimmed.data(), trimmed.size());
        } else {
          value.append(std::string{line} + "\n");
        }
      }
      // Separate erase/insert calls required due to the value type being constant; this prevents
      // the use of the [] operator. Can leverage insert_or_assign in C++17 in the future.
      values_.erase(full_prefix);
      values_.insert({full_prefix, SnapshotImpl::createEntry(value)});
    }
  }
}

LoaderImpl::LoaderImpl(RandomGenerator& generator, Stats::Store& store,
                       ThreadLocal::SlotAllocator& tls)
    : LoaderImpl(DoNotLoadSnapshot{}, generator, store, tls) {
  loadNewSnapshot();
}

LoaderImpl::LoaderImpl(DoNotLoadSnapshot /* unused */, RandomGenerator& generator,
                       Stats::Store& store, ThreadLocal::SlotAllocator& tls)
    : generator_(generator), stats_(generateStats(store)), admin_layer_(stats_),
      tls_(tls.allocateSlot()) {}

std::unique_ptr<SnapshotImpl> LoaderImpl::createNewSnapshot() {
  std::vector<Snapshot::OverrideLayerConstPtr> layers;
  layers.emplace_back(std::make_unique<const AdminLayer>(admin_layer_));
  return std::make_unique<SnapshotImpl>(generator_, stats_, std::move(layers));
}

void LoaderImpl::loadNewSnapshot() {
  ThreadLocal::ThreadLocalObjectSharedPtr ptr = createNewSnapshot();
  tls_->set([ptr = std::move(ptr)](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
    return ptr;
  });
}

Snapshot& LoaderImpl::snapshot() { return tls_->getTyped<Snapshot>(); }

void LoaderImpl::mergeValues(const std::unordered_map<std::string, std::string>& values) {
  admin_layer_.mergeValues(values);
  loadNewSnapshot();
}

DiskBackedLoaderImpl::DiskBackedLoaderImpl(Event::Dispatcher& dispatcher,
                                           ThreadLocal::SlotAllocator& tls,
                                           const std::string& root_symlink_path,
                                           const std::string& subdir,
                                           const std::string& override_dir, Stats::Store& store,
                                           RandomGenerator& generator)
    : LoaderImpl(DoNotLoadSnapshot{}, generator, store, tls),
      watcher_(dispatcher.createFilesystemWatcher()), root_path_(root_symlink_path + "/" + subdir),
      override_path_(root_symlink_path + "/" + override_dir) {
  watcher_->addWatch(root_symlink_path, Filesystem::Watcher::Events::MovedTo,
                     [this](uint32_t) -> void { loadNewSnapshot(); });

  loadNewSnapshot();
}

RuntimeStats LoaderImpl::generateStats(Stats::Store& store) {
  std::string prefix = "runtime.";
  RuntimeStats stats{
      ALL_RUNTIME_STATS(POOL_COUNTER_PREFIX(store, prefix), POOL_GAUGE_PREFIX(store, prefix))};
  return stats;
}

std::unique_ptr<SnapshotImpl> DiskBackedLoaderImpl::createNewSnapshot() {
  std::vector<Snapshot::OverrideLayerConstPtr> layers;
  try {
    layers.push_back(std::make_unique<DiskLayer>("root", root_path_));
    if (Filesystem::directoryExists(override_path_)) {
      layers.push_back(std::make_unique<DiskLayer>("override", override_path_));
      stats_.override_dir_exists_.inc();
    } else {
      stats_.override_dir_not_exists_.inc();
    }
  } catch (EnvoyException& e) {
    layers.clear();
    stats_.load_error_.inc();
    ENVOY_LOG(debug, "error loading runtime values from disk: {}", e.what());
  }
  layers.push_back(std::make_unique<AdminLayer>(admin_layer_));
  return std::make_unique<SnapshotImpl>(generator_, stats_, std::move(layers));
}

} // namespace Runtime
} // namespace Envoy
