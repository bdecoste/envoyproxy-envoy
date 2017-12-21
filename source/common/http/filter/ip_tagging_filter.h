#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <arpa/inet.h>

#include "envoy/http/filter.h"
#include "envoy/json/json_object.h"

#include "common/common/assert.h"
#include "common/json/config_schemas.h"
#include "common/json/json_validator.h"
#include "common/network/cidr_range.h"
#include "common/network/utility.h"

namespace Envoy {
namespace Http {

/**
 * Type of requests the filter should apply to.
 */
enum class FilterRequestType { Internal, External, Both };

/**
 * Configuration for the ip tagging filter.
 */
class IpTaggingFilterConfig : Json::Validator {
public:
  IpTaggingFilterConfig(const Json::Object& json_config)
      : Json::Validator(json_config, Json::Schema::IP_TAGGING_HTTP_FILTER_SCHEMA),
        request_type_(stringToType(json_config.getString("request_type", "both"))) {}

  FilterRequestType requestType() const { return request_type_; }

private:
  static FilterRequestType stringToType(const std::string& request_type) {
    if (request_type == "internal") {
      return FilterRequestType::Internal;
    } else if (request_type == "external") {
      return FilterRequestType::External;
    } else {
      ASSERT(request_type == "both");
      return FilterRequestType::Both;
    }
  }

  const FilterRequestType request_type_;
};

typedef std::shared_ptr<IpTaggingFilterConfig> IpTaggingFilterConfigSharedPtr;

/**
 * A filter that tags requests via the x-envoy-ip-tags header based on the request's trusted XFF
 * address.
 */
class IpTaggingFilter : public StreamDecoderFilter {
public:
  IpTaggingFilter(IpTaggingFilterConfigSharedPtr config);
  ~IpTaggingFilter();

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  FilterHeadersStatus decodeHeaders(HeaderMap& headers, bool end_stream) override;
  FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;
  FilterTrailersStatus decodeTrailers(HeaderMap& trailers) override;
  void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) override;

private:
  IpTaggingFilterConfigSharedPtr config_;
  StreamDecoderFilterCallbacks* callbacks_{};
};


class Node {
public:
  Node() : is_node_(true) {}
  Node(Network::Address::CidrRange cidr_range, const std::string& tag, int curr_bit, int skip) : cidr_(cidr_range), curr_bit_(curr_bit), skip_(skip) {tags_.push_back(tag);}

  bool isNode() { return is_node_; }
  void setTags(std::string& tag) { tags_.push_back(tag); }
  std::vector<std::string> getTags() { return tags_; }


  std::vector<std::string> tags_;
  bool is_node_{true}; // TODO: change it to check left/right aren't empty nullptrs
  // might be able to have a const object
  // I think the node should hold the object for CidrRange so this should in the end be a unique_ptr
  // and not just an object?
  Network::Address::CidrRange cidr_;
  // where to start with the bit counting
  // might be able to use this for is node check instead of a bool
  // test for off by one
  int curr_bit_{-1};
  /// how many bits to skip - useful when splitting
  // to figure out do i let this be -1 until one of the children is populated?
  int skip_{-1};
  // 0 bit
  std::unique_ptr<Node> left_;
  // 1 bit
  std::unique_ptr<Node> right_;
};

// TODO handle ipv6 code assumes ipv4
class IpTrie {
public:
  IpTrie() : root_(new Node()) {}
  ~IpTrie() {}
  // this modifies the object
  void insert(Network::Address::CidrRange cidr_range, const std::string& tag) {
    //int curr_bit = 1;
    // need to keep track of cidr range length ie stop at that point
    uint32_t address = ntohl(cidr_range.ip()->ipv4()->address());
    //int bit_mask_length = cidr_range.length();
    // first insert
    int side_bit = getBit(address, 1);
    bool init = false;
    // or is it root_->left_.get()?
    if (side_bit == 0 && !root_->left_.get()) {
      root_->left_.reset(new Node(cidr_range, tag,1, -1));
      init = true;
    } else if (side_bit == 1 && !root_->right_.get()) {
      root_->right_.reset(new Node(cidr_range, tag, 1, -1));
      init = true;
    }
    if (init) {
      size_++;
      return;
    }

    //int length = cidr_range.length();

    int skip;
    Node* parent_ = root_.get();
    side_bit = getBit(address, curr_bit);
    Node* curr_node = (side_bit == 0 ? root_->left_.get() : root_->right_.get());
    // curr_node and address have matching bits up until curr_bits
    while(curr_node) {
      //check if they are the same if so just add another tag
      // question in the end should this hold all cidr ranges that map to it and their tags
      //if so turn it into a tag
      if(curr_node->cidr_range_ == cidr_range) {
        curr_node->setTags(tag);
        return;
      }
      uint32t_t curr_node_address = ntohl(curr_node->cidr_.ip().ipv4->address());
       skip = 1;
      // add length check here
      while (getAddress(curr_node_address, curr_bit+skip) == getAddress(address, curr_bit+skip))
      {
        skip++;
      }
      skip--;
      //make sure that between the current bit and the number of skips that they match
      // and if curr_bit+ skip is over length then we can stop at length and split the tree
      // underneath
      // what about skip_ -1?
      if (curr_node->skip_ != skip) {
       // break and insert
        break;
      } else {
        // if they match keep on going further
        curr_bit += curr_node->skip_;

      }
      parent_ = curr_node;
      curr_node = getBit(address, curr_bit) == 0 ? curr_node->left_.get(): curr_node->right_.get();
    }

    // find at which bit they diverge
    // two addresses we start at curr_bit and go until they diverge


    // if node do this
    // need to calculate skip between parent and new child
    // assume parent isn't the root  how am i going to deal with the root then
    //find out when two addresses diverge
    // the case that !curr_node
    if(!curr_node) {
      // update parent node skip number
      side_bit = getBit(address, curr_bit);
      parent_->skip_ = skip;
      if (side_bit == 0) {
        parent_->left_.reset(new Node(cidr_range, tag, curr_bit, -1));
      } else {
        parent_->right_.reset(new Node(cidr_range, tag, curr_bit, -1));
      }
    } else {
      // insert in between two things
    }
    size_++;
      //traverse until we find either a perfect match or

    // 1. insert at root aka leaf
    // 2. insert split
    // 3. insert and node already exists
    // 4. what about cidr length? do we stop caring about bits once length has been met?
  }

  // string is passed in since it is pulled from xff
  std::vector<std::string> getTags(const std::string& address_str) const {
    // check for empty trie
    if (size_ == 0) {
      return std::vector<std::string>();
    }

    std::vector<std::string> return_list;
    int curr_bit = 1;

    // assume this is ipv4 need to generalize to ipv6
    Network::Address::InstanceConstSharedPtr address_ptr = Network::Utility::parseInternetAddress(address_str);
    uint32_t address = (address_ptr->ip()->ipv4()->address());
    // add a test case for both 0/1 split at the top
    //Node& curr_node = (getBit(address, curr_bit) == 0 ? *(root_->left_) : *(root_->right_));
    Node* curr_node = (getBit(address, curr_bit) == 0 ? root_->left_.get() : root_->right_.get());
    // HACK what would be the requirement to get out
    //while (!curr_node.isNode()) {
    while (curr_node) {
      // do we need to check current bit?
      // abstract out 32

      // once curr_node bit matches the address passed in
      // do we need to check
      // if the address current bit we are looping over is withing the cidr range of this current
      // node

      // might be able to replace the above with something like this if ( (32 - curr_bit) >
      // curr_node.cidr_.length() )
//      if (curr_node.cidr_.isInRange(*address_ptr)) {
//        return_list.insert(return_list.end(), curr_node.tags_.begin(), curr_node.tags_.end());
//      }
      if (curr_node->cidr_.isInRange(*address_ptr)) {
        return_list.insert(return_list.end(), curr_node->tags_.begin(), curr_node->tags_.end());
      }
      // in the else case can we just exit at this point?
      // keep on looping // check for off by 1
      // should the logic be skip is always 1 unless set to something else?  or 1 then we if we do 2
      // 1000
      // 1001
      // should we check for left before nxt step
      //curr_bit += curr_node.skip_;
      // Need to check curr through curr + skip that they overlap
      uint32_t curr_node_address = (curr_node->cidr_.ip()->ipv4()->address());
//      while(int skip =1 <= curr_node.skip_) {
//        if(getBit())
//        skip++;
//      }
//      if (skip > 1) { // check overlap}
//        curr_node = (getBit(address, curr_bit) == 0 ? *(curr_node.right_): *(curr_node.left_));
//        // when do we check for left vs right existing
//      }
      // only do if skip_ > 0
      // when it is more than 1 bit to match on 1 means we go to the next
//      if(curr_node->skip_ > 1  && match(curr_node_address, address, curr_bit, curr_node->skip_)) {
//        std::cout << "match" << std::endl;
//        curr_bit += curr_node->skip_;
//      }
      if (!match(curr_node_address, address, curr_bit, curr_node->skip_-1)) {
        break;
      }
      curr_bit += curr_node->skip_;
      curr_node = getBit(address, curr_bit) == 0 ? curr_node->left_.get(): curr_node->right_.get();
  }

    // do a final check does
    return return_list;
  }

  int size() const { return size_; }

private:
  static int getBit(uint32_t address, int bit) {
    if ( bit <=0 || bit >= 32) {
      return -1;
    }
    return address >> (32-bit) & 1;
  }
  // make this generic for ipv6 data structure
  // what about when num_bits == 0?
  static bool match(uint32_t address1, uint32_t address2, int start, int num_bits) {
//
    if (num_bits == 0){
      return true;
    }
    int curr_bit = start;
    while(curr_bit <= start + num_bits){
        if (getBit(address1, curr_bit) != getBit(address2, curr_bit)) {
          return false;
        }
      curr_bit++;
    }
    return true;

  }

  // prob can make it jsut be an object here
  std::unique_ptr<Node> root_;
  int size_{0}; // Number of nodes in the tree;
};

} // namespace Http
} // namespace Envoy
