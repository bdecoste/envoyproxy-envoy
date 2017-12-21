#include "common/buffer/buffer_impl.h"
#include "common/http/filter/ip_tagging_filter.h"
#include "common/http/header_map_impl.h"
#include "common/http/headers.h"

#include "test/mocks/http/mocks.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::Return;
using testing::_;

namespace Envoy {
namespace Http {

class IpTaggingFilterTest : public testing::Test {
public:
  const std::string internal_request_json = R"EOF(
    {
      "request_type" : "internal",
      "ip_tags" : [
        {
          "ip_tag_name" : "test_internal",
          "ip_list" : ["1.2.3.4"]
        }
      ]
    }
  )EOF";

  const std::string external_request_json = R"EOF(
    {
      "request_type" : "external",
      "ip_tags" : [
        {
          "ip_tag_name" : "test_external",
          "ip_list" : ["1.2.3.4"]
        }
      ]
    }
  )EOF";

  const std::string both_request_json = R"EOF(
    {
      "request_type" : "both",
      "ip_tags" : [
        {
          "ip_tag_name" : "test_both",
          "ip_list" : ["1.2.3.4"]
        }
      ]
    }
  )EOF";

  void SetUpTest(const std::string json) {
    Json::ObjectSharedPtr config = Json::Factory::loadFromString(json);
    config_.reset(new IpTaggingFilterConfig(*config));
    filter_.reset(new IpTaggingFilter(config_));
    filter_->setDecoderFilterCallbacks(filter_callbacks_);
  }

  ~IpTaggingFilterTest() { filter_->onDestroy(); }

  IpTaggingFilterConfigSharedPtr config_;
  std::unique_ptr<IpTaggingFilter> filter_;
  NiceMock<MockStreamDecoderFilterCallbacks> filter_callbacks_;
  TestHeaderMapImpl request_headers_;
  Buffer::OwnedImpl data_;
};

TEST_F(IpTaggingFilterTest, InternalRequest) {
  SetUpTest(internal_request_json);

  EXPECT_EQ(FilterHeadersStatus::Continue, filter_->decodeHeaders(request_headers_, false));
  EXPECT_EQ(FilterDataStatus::Continue, filter_->decodeData(data_, false));
  EXPECT_EQ(FilterTrailersStatus::Continue, filter_->decodeTrailers(request_headers_));
}

TEST_F(IpTaggingFilterTest, ExternalRequest) {
  SetUpTest(external_request_json);

  EXPECT_EQ(FilterHeadersStatus::Continue, filter_->decodeHeaders(request_headers_, false));
  EXPECT_EQ(FilterDataStatus::Continue, filter_->decodeData(data_, false));
  EXPECT_EQ(FilterTrailersStatus::Continue, filter_->decodeTrailers(request_headers_));
}

TEST_F(IpTaggingFilterTest, BothRequest) {
  SetUpTest(both_request_json);

  EXPECT_EQ(FilterHeadersStatus::Continue, filter_->decodeHeaders(request_headers_, false));
  EXPECT_EQ(FilterDataStatus::Continue, filter_->decodeData(data_, false));
  EXPECT_EQ(FilterTrailersStatus::Continue, filter_->decodeTrailers(request_headers_));
}

class IpTrieTest : public testing::Test {
public:
  void SetUpTest(std::vector<Network::Address::CidrRange> list, const std::string& tag) {
    trie_.reset(new IpTrie());
    for (const auto a : list) {
      trie_->insert(a, tag);
    }
  }

  std::unique_ptr<IpTrie> trie_;
};

TEST_F(IpTrieTest, NoMatch) {
// InstanceConstSharedPtr address = Utility::parseInternetAddress("1.2.3.5");
std::string address("10.191.3.5");
// do i really need to do this?
trie_.reset(new IpTrie());
// Test empty trie
EXPECT_EQ(0, trie_->size());
EXPECT_EQ(0, trie_->getTags(address).size());
std::cout << "empty good" << std::endl;
// Test no match
std::vector<Network::Address::CidrRange> list{
  Network::Address::CidrRange::create("10.255.255.255/10")};
SetUpTest(list, "test");
EXPECT_EQ(0, trie_->getTags(address).size());


std::vector<Network::Address::CidrRange> list1{
  Network::Address::CidrRange::create("204.255.255.255/10")};
SetUpTest(list1, "bob");
EXPECT_EQ(0, trie_->getTags(address).size());

// TODO: add ipv6
// Test with Ipv6 as well
}

TEST_F(IpTrieTest, OneMatch) {
// TODO: show what this structure looks like
std::string address("1.2.3.4");
std::vector<Network::Address::CidrRange> list1{
  Network::Address::CidrRange::create("1.2.3.4/24")};
SetUpTest(list1, "bob");
EXPECT_EQ(1, trie_->getTags(address).size());
//EXPECT_EQ("bob", trie_->getTags(address)[0]);

std::vector<Network::Address::CidrRange> list{
  Network::Address::CidrRange::create("1.2.3.4/24"),
 // Network::Address::CidrRange::create("1.2.3.4/31"),
  Network::Address::CidrRange::create("10.255.255.255/10")};
SetUpTest(list, "test");

// EXPECT_EQ("test", trie_->getTags(address)[0]);
EXPECT_EQ(1, trie_->getTags(address).size());
//EXPECT_EQ("test", trie_->getTags(address)[0]);
std::string address2("10.255.255.255");
// EXPECT_EQ("test", trie_->getTags(address2)[0]);
}

TEST_F(IpTrieTest, MultipleMatches) {
std::vector<Network::Address::CidrRange> list{Network::Address::CidrRange::create("1.2.3.0/24"),
                                              Network::Address::CidrRange::create("1.2.3.4/32")};
// TODO: come up with test data prob 1.2.3.0/24 and then something 1.2.3.4/32 with two diff
SetUpTest(list, "multiple");

EXPECT_EQ(2, trie_->getTags("1.2.3.4").size());
// check both are multiple
// TODO: optimize the code to many remove multiple hits in getTags?
}

// TODO: add test for multiple tags at a the same node

//TEST_F(IpTrieTest, InvalidInputTests) { EXPECT_THROW(trie_->getTags("123"), EnvoyException); }

// More tests to add
/**
 * 1. test taht are recursive and do both splits of the tree ie left and right.
 * 2. off by one for skip stuff.
 * 3. getbit test
 * 4. test for /0 prob store it at the root
 * 5. reinserting the same node in the format of different cidr range representation
 * 6. all zeros
 * 7. all 1.s
 * 8 /1 and /32  length of the cidr range
 */

} // namespace Http
} // namespace Envoy
