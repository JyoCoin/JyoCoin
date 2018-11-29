// Copyright (c) 2018 Jyocoin Project, Derived from 2017-2018, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#ifndef jyocoin_PROTOCOL_H
#define jyocoin_PROTOCOL_H

#include "trezor_defs.hpp"
#include "device/device_cold.hpp"
#include "messages_map.hpp"
#include "transport.hpp"
#include "wallet/wallet2.h"

namespace hw{
namespace trezor{
namespace protocol{

  std::string key_to_string(const ::crypto::ec_point & key);
  std::string key_to_string(const ::crypto::ec_scalar & key);
  std::string key_to_string(const ::crypto::hash & key);
  std::string key_to_string(const ::rct::key & key);

  void string_to_key(::crypto::ec_scalar & key, const std::string & str);
  void string_to_key(::crypto::ec_point & key, const std::string & str);
  void string_to_key(::rct::key & key, const std::string & str);

  template<class sub_t, class InputIterator>
  void assign_to_repeatable(::google::protobuf::RepeatedField<sub_t> * dst, const InputIterator begin, const InputIterator end){
    for (InputIterator it = begin; it != end; it++) {
      auto s = dst->Add();
      *s = *it;
    }
  }

  template<class sub_t, class InputIterator>
  void assign_from_repeatable(std::vector<sub_t> * dst, const InputIterator begin, const InputIterator end){
    for (InputIterator it = begin; it != end; it++) {
      dst->push_back(*it);
    }
  };

  template<typename T>
  bool cn_deserialize(const void * buff, size_t len, T & dst){
    std::stringstream ss;
    ss.write(static_cast<const char *>(buff), len);  //ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, dst);
    return r;
  }

  template<typename T>
  bool cn_deserialize(const std::string & str, T & dst){
    return cn_deserialize(str.data(), str.size(), dst);
  }

  template<typename T>
  std::string cn_serialize(T & obj){
    std::ostringstream oss;
    binary_archive<true> oar(oss);
    bool success = ::serialization::serialize(oar, obj);
    if (!success){
      throw exc::EncodingException("Could not CN serialize given object");
    }
    return oss.str();
  }

// Crypto / encryption
namespace crypto {
namespace chacha {

  /**
   * Chacha20Poly1305 decryption with tag verification. RFC 7539.
   */
  void decrypt(const void* ciphertext, size_t length, const uint8_t* key, const uint8_t* iv, char* plaintext);

}
}


// Cold Key image sync
namespace ki {

  using jyocoinTransferDetails = messages::jyocoin::jyocoinKeyImageSyncStepRequest_jyocoinTransferDetails;
  using jyocoinSubAddressIndicesList = messages::jyocoin::jyocoinKeyImageExportInitRequest_jyocoinSubAddressIndicesList;
  using jyocoinExportedKeyImage = messages::jyocoin::jyocoinKeyImageSyncStepAck_jyocoinExportedKeyImage;
  using exported_key_image = hw::device_cold::exported_key_image;

  /**
   * Converts transfer details to the jyocoinTransferDetails required for KI sync
   */
  bool key_image_data(wallet_shim * wallet,
                      const std::vector<tools::wallet2::transfer_details> & transfers,
                      std::vector<jyocoinTransferDetails> & res);

  /**
   * Computes a hash over jyocoinTransferDetails. Commitment used in the KI sync.
   */
  std::string compute_hash(const jyocoinTransferDetails & rr);

  /**
   * Generates KI sync request with commitments computed.
   */
  void generate_commitment(std::vector<jyocoinTransferDetails> & mtds,
                           const std::vector<tools::wallet2::transfer_details> & transfers,
                           std::shared_ptr<messages::jyocoin::jyocoinKeyImageExportInitRequest> & req);

}

// Cold transaction signing
namespace tx {
  using TsxData = messages::jyocoin::jyocoinTransactionInitRequest_jyocoinTransactionData;
  using jyocoinTransactionDestinationEntry = messages::jyocoin::jyocoinTransactionDestinationEntry;
  using jyocoinAccountPublicAddress = messages::jyocoin::jyocoinTransactionDestinationEntry_jyocoinAccountPublicAddress;
  using jyocoinTransactionSourceEntry = messages::jyocoin::jyocoinTransactionSourceEntry;
  using jyocoinMultisigKLRki = messages::jyocoin::jyocoinTransactionSourceEntry_jyocoinMultisigKLRki;
  using jyocoinOutputEntry = messages::jyocoin::jyocoinTransactionSourceEntry_jyocoinOutputEntry;
  using jyocoinRctKey = messages::jyocoin::jyocoinTransactionSourceEntry_jyocoinOutputEntry_jyocoinRctKeyPublic;
  using jyocoinRsigData = messages::jyocoin::jyocoinTransactionRsigData;

  using tx_construction_data = tools::wallet2::tx_construction_data;
  using unsigned_tx_set = tools::wallet2::unsigned_tx_set;

  void translate_address(jyocoinAccountPublicAddress * dst, const cryptonote::account_public_address * src);
  void translate_dst_entry(jyocoinTransactionDestinationEntry * dst, const cryptonote::tx_destination_entry * src);
  void translate_src_entry(jyocoinTransactionSourceEntry * dst, const cryptonote::tx_source_entry * src);
  void translate_klrki(jyocoinMultisigKLRki * dst, const rct::multisig_kLRki * src);
  void translate_rct_key(jyocoinRctKey * dst, const rct::ctkey * src);
  std::string hash_addr(const jyocoinAccountPublicAddress * addr, boost::optional<uint64_t> amount = boost::none, boost::optional<bool> is_subaddr = boost::none);
  std::string hash_addr(const std::string & spend_key, const std::string & view_key, boost::optional<uint64_t> amount = boost::none, boost::optional<bool> is_subaddr = boost::none);
  std::string hash_addr(const ::crypto::public_key * spend_key, const ::crypto::public_key * view_key, boost::optional<uint64_t> amount = boost::none, boost::optional<bool> is_subaddr = boost::none);

  typedef boost::variant<rct::rangeSig, rct::Bulletproof> rsig_v;

  /**
   * Transaction signer state holder.
   */
  class TData {
  public:
    TsxData tsx_data;
    tx_construction_data tx_data;
    cryptonote::transaction tx;
    bool in_memory;
    unsigned rsig_type;
    std::vector<uint64_t> grouping_vct;
    std::shared_ptr<jyocoinRsigData> rsig_param;
    size_t cur_input_idx;
    size_t cur_output_idx;
    size_t cur_batch_idx;
    size_t cur_output_in_batch_idx;

    std::vector<std::string> tx_in_hmacs;
    std::vector<std::string> tx_out_entr_hmacs;
    std::vector<std::string> tx_out_hmacs;
    std::vector<rsig_v> tx_out_rsigs;
    std::vector<rct::ctkey> tx_out_pk;
    std::vector<rct::ecdhTuple> tx_out_ecdh;
    std::vector<size_t> source_permutation;
    std::vector<std::string> alphas;
    std::vector<std::string> spend_encs;
    std::vector<std::string> pseudo_outs;
    std::vector<std::string> pseudo_outs_hmac;
    std::vector<std::string> couts;
    std::vector<std::string> couts_dec;
    std::vector<rct::key> rsig_gamma;
    std::string tx_prefix_hash;
    std::string enc_salt1;
    std::string enc_salt2;
    std::string enc_keys;

    std::shared_ptr<rct::rctSig> rv;

    TData();
  };

  class Signer {
  private:
    TData m_ct;
    wallet_shim * m_wallet2;

    size_t m_tx_idx;
    const unsigned_tx_set * m_unsigned_tx;
    hw::tx_aux_data * m_aux_data;

    bool m_multisig;

    const tx_construction_data & cur_tx(){
      CHECK_AND_ASSERT_THROW_MES(m_tx_idx < m_unsigned_tx->txes.size(), "Invalid transaction index");
      return m_unsigned_tx->txes[m_tx_idx];
    }

    void extract_payment_id();
    void compute_integrated_indices(TsxData * tsx_data);

  public:
    Signer(wallet_shim * wallet2, const unsigned_tx_set * unsigned_tx, size_t tx_idx = 0, hw::tx_aux_data * aux_data = nullptr);

    std::shared_ptr<messages::jyocoin::jyocoinTransactionInitRequest> step_init();
    void step_init_ack(std::shared_ptr<const messages::jyocoin::jyocoinTransactionInitAck> ack);

    std::shared_ptr<messages::jyocoin::jyocoinTransactionSetInputRequest> step_set_input(size_t idx);
    void step_set_input_ack(std::shared_ptr<const messages::jyocoin::jyocoinTransactionSetInputAck> ack);

    void sort_ki();
    std::shared_ptr<messages::jyocoin::jyocoinTransactionInputsPermutationRequest> step_permutation();
    void step_permutation_ack(std::shared_ptr<const messages::jyocoin::jyocoinTransactionInputsPermutationAck> ack);

    std::shared_ptr<messages::jyocoin::jyocoinTransactionInputViniRequest> step_set_vini_input(size_t idx);
    void step_set_vini_input_ack(std::shared_ptr<const messages::jyocoin::jyocoinTransactionInputViniAck> ack);

    std::shared_ptr<messages::jyocoin::jyocoinTransactionAllInputsSetRequest> step_all_inputs_set();
    void step_all_inputs_set_ack(std::shared_ptr<const messages::jyocoin::jyocoinTransactionAllInputsSetAck> ack);

    std::shared_ptr<messages::jyocoin::jyocoinTransactionSetOutputRequest> step_set_output(size_t idx);
    void step_set_output_ack(std::shared_ptr<const messages::jyocoin::jyocoinTransactionSetOutputAck> ack);

    std::shared_ptr<messages::jyocoin::jyocoinTransactionAllOutSetRequest> step_all_outs_set();
    void step_all_outs_set_ack(std::shared_ptr<const messages::jyocoin::jyocoinTransactionAllOutSetAck> ack, hw::device &hwdev);

    std::shared_ptr<messages::jyocoin::jyocoinTransactionSignInputRequest> step_sign_input(size_t idx);
    void step_sign_input_ack(std::shared_ptr<const messages::jyocoin::jyocoinTransactionSignInputAck> ack);

    std::shared_ptr<messages::jyocoin::jyocoinTransactionFinalRequest> step_final();
    void step_final_ack(std::shared_ptr<const messages::jyocoin::jyocoinTransactionFinalAck> ack);

    std::string store_tx_aux_info();

    bool in_memory() const {
      return m_ct.in_memory;
    }

    bool is_simple() const {
      if (!m_ct.rv){
        throw std::invalid_argument("RV not initialized");
      }
      auto tp = m_ct.rv->type;
      return tp == rct::RCTTypeSimple;
    }

    bool is_req_bulletproof() const {
      return m_ct.tx_data.use_bulletproofs;
    }

    bool is_bulletproof() const {
      if (!m_ct.rv){
        throw std::invalid_argument("RV not initialized");
      }
      auto tp = m_ct.rv->type;
      return tp == rct::RCTTypeBulletproof;
    }

    bool is_offloading() const {
      return m_ct.rsig_param && m_ct.rsig_param->offload_type() != 0;
    }

    size_t num_outputs() const {
      return m_ct.tx_data.splitted_dsts.size();
    }

    size_t num_inputs() const {
      return m_ct.tx_data.sources.size();
    }

    const TData & tdata() const {
      return m_ct;
    }
  };

}

}
}
}


#endif //jyocoin_PROTOCOL_H
