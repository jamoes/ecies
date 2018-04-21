require 'spec_helper'

describe ECIES::Crypt do

  describe 'Encryption and decryption' do

    it 'Encrypts and decrypts' do
      key = OpenSSL::PKey::EC.new('secp256k1').generate_key
      crypt = ECIES::Crypt.new

      encrypted = crypt.encrypt(key, 'secret')
      expect(crypt.decrypt(key, encrypted)).to eq 'secret'

      expect{ ECIES::Crypt.new(mac_length: :full).decrypt(key, encrypted) }.to raise_error(OpenSSL::PKey::ECError)
      expect{ ECIES::Crypt.new(mac_digest: 'sha512').decrypt(key, encrypted) }.to raise_error(OpenSSL::PKey::ECError)
    end

    it 'Supports hex-encoded keys' do
      key = OpenSSL::PKey::EC.new('secp256k1').generate_key
      public_key_hex = key.public_key.to_bn.to_s(16)
      private_key_hex = key.private_key.to_s(16)

      public_key = ECIES::Crypt.public_key_from_hex(public_key_hex)
      private_key = ECIES::Crypt.private_key_from_hex(private_key_hex)

      expect(public_key.public_key).to eq key.public_key
      expect(private_key.private_key).to eq key.private_key

      expect{ ECIES::Crypt.public_key_from_hex(public_key_hex, 'secp224k1') }.to raise_error(OpenSSL::PKey::EC::Point::Error)
      expect{ ECIES::Crypt.private_key_from_hex(private_key_hex, 'secp224k1') }.to raise_error(OpenSSL::PKey::ECError)
      expect{ ECIES::Crypt.private_key_from_hex("00") }.to raise_error(OpenSSL::PKey::ECError)
    end

    it 'Supports other EC curves' do
      key = OpenSSL::PKey::EC.new('secp224k1').generate_key
      crypt = ECIES::Crypt.new

      encrypted = crypt.encrypt(key, 'secret')
      expect(crypt.decrypt(key, encrypted)).to eq 'secret'
    end

    context 'known value' do
      before(:all) do
        OpenSSL::PKey::EC.class_eval do
          # Overwrites `generate_key` for both the key generated below, and the
          # ephemeral_key generated in the `encrypt` method.
          def generate_key
            self.private_key = 2
            self.public_key = group.generator.mul(private_key)
            self
          end
        end

        @key = OpenSSL::PKey::EC.new('secp256k1').generate_key
      end

      [
        [ECIES::Crypt.new, "\x02\xC6\x04\x7F\x94A\xED}m0E@n\x95\xC0|\xD8\\w\x8EK\x8C\xEF<\xA7\xAB\xAC\t\xB9\\p\x9E\xE5B;\x12:\x17\xCE\x84\xAB\x9F\x0E%\xCD\x94~\x1E\xBC\x89$\x11\xEE6\xE4".b],
        [ECIES::Crypt.new(mac_length: :full), "\x02\xC6\x04\x7F\x94A\xED}m0E@n\x95\xC0|\xD8\\w\x8EK\x8C\xEF<\xA7\xAB\xAC\t\xB9\\p\x9E\xE5B;\x12:\x17\xCEo\x9B\xA7\x955\x89\x9FR\xDF\x1C\xED\x00\x86<\n\x04\v\xD6(\x9D\xF5\xF9\x13\xC8/\xD7os(ZsF".b],
        [ECIES::Crypt.new(digest: 'sha512', mac_length: :full), "\x02\xC6\x04\x7F\x94A\xED}m0E@n\x95\xC0|\xD8\\w\x8EK\x8C\xEF<\xA7\xAB\xAC\t\xB9\\p\x9E\xE5%\r^\xA9\xD9\xDC\xFB\xD7\x14b\xB4\x00\x84\xABl\xEAh\x0Fc\x805\xAF\x1DT\x05\x87`\xA5\xC4\xB7\xB5r\xF6\x89\xB1U0\x0E \xD4\x1E\x16\x184\xE9:\xE7\x951\xF4\xB3\x93\"A\x85\x1F\x9A\x8E\xAD\xE1(\x1D\xB3\xC4\x15\xD3\xB1\xA8\xFB\x1D".b],
        [ECIES::Crypt.new(cipher: 'aes-256-cbc', mac_length: :full), "\x02\xC6\x04\x7F\x94A\xED}m0E@n\x95\xC0|\xD8\\w\x8EK\x8C\xEF<\xA7\xAB\xAC\t\xB9\\p\x9E\xE5\x1Fj\x04N\eg($\xD4\xFBD\xFFd\xA1\xA3z\x90T#\x1D\x12{3IM\x93!|\xA5\xAF&\xD4+;\e\xA6i.wD\x1F\xCB\xE1\x90{\xB6\x8B\xAF".b],
        [ECIES::Crypt.new(mac_digest: 'sha256', kdf_digest: 'sha512'), "\x02\xC6\x04\x7F\x94A\xED}m0E@n\x95\xC0|\xD8\\w\x8EK\x8C\xEF<\xA7\xAB\xAC\t\xB9\\p\x9E\xE5%\r^\xA9\xD9\xDC\xF5\\\x9A\x04\xE0T\x91\xEA=\xA6W\x84X\xBB\xCA\xB4".b],
      ].each do |crypt, expected_value|
        it "matches for #{crypt.to_s}" do
          encrypted = crypt.encrypt(@key, 'secret')
          expect(encrypted).to eq expected_value
          expect(crypt.decrypt(@key, encrypted)).to eq 'secret'
        end
      end
    end

    it '#to_s' do
      [
        [ECIES::Crypt.new,                                             "KDF-SHA256_HMAC-SHA-256-128_AES-256-CTR"],
        [ECIES::Crypt.new(mac_length: :full),                          "KDF-SHA256_HMAC-SHA-256-256_AES-256-CTR"],
        [ECIES::Crypt.new(digest: 'sha512'),                           "KDF-SHA512_HMAC-SHA-512-256_AES-256-CTR"],
        [ECIES::Crypt.new(mac_digest: 'sha512'),                       "KDF-SHA256_HMAC-SHA-512-256_AES-256-CTR"],
        [ECIES::Crypt.new(mac_digest: 'sha512', kdf_digest: 'sha224'), "KDF-SHA224_HMAC-SHA-512-256_AES-256-CTR"],
        [ECIES::Crypt.new(cipher: 'aes-128-cbc'),                      "KDF-SHA256_HMAC-SHA-256-128_AES-128-CBC"],
      ].each do |crypt, expected_value|
        expect(crypt.to_s).to eq expected_value
      end
    end

    it 'Raises on unknown cipher or digest' do
      key = OpenSSL::PKey::EC.new('secp256k1').generate_key

      expect{ ECIES::Crypt.new(digest: 'foo') }.to raise_error(RuntimeError)
      expect{ ECIES::Crypt.new(digest: 'md5') }.to raise_error(RuntimeError)
      expect{ ECIES::Crypt.new(cipher: 'foo') }.to raise_error(RuntimeError)
      expect{ ECIES::Crypt.new(cipher: 'aes-256-gcm') }.to raise_error(RuntimeError)
    end

    it 'Raises when key is missing' do
      key = OpenSSL::PKey::EC.new

      expect{ ECIES::Crypt.new.encrypt(key, 'secret') }.to raise_error(RuntimeError)
      expect{ ECIES::Crypt.new.decrypt(key, 'secret') }.to raise_error(RuntimeError)
    end
  end

  describe '#kdf' do
    it 'derives keys correctly' do
      sha256_test_vectors = [
        # [shared_secret, shared_info, expected_key]
        ['96c05619d56c328ab95fe84b18264b08725b85e33fd34f08', '', '443024c3dae66b95e6f5670601558f71'],
        ['96f600b73ad6ac5629577eced51743dd2c24c21b1ac83ee4', '', 'b6295162a7804f5667ba9070f82fa522'],
        ['22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d', '75eef81aa3041e33b80971203d2c0c52', 'c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21'],
        ['7e335afa4b31d772c0635c7b0e06f26fcd781df947d2990a', 'd65a4812733f8cdbcdfb4b2f4c191d87', 'c0bd9e38a8f9de14c2acd35b2f3410c6988cf02400543631e0d6a4c1d030365acbf398115e51aaddebdc9590664210f9aa9fed770d4c57edeafa0b8c14f93300865251218c262d63dadc47dfa0e0284826793985137e0a544ec80abf2fdf5ab90bdaea66204012efe34971dc431d625cd9a329b8217cc8fd0d9f02b13f2f6b0b'],
      ]

      sha256_test_vectors.each do |shared_secret, shared_info, expected_key|
        shared_secret = [shared_secret].pack('H*')
        shared_info = [shared_info].pack('H*')
        expected_key = [expected_key].pack('H*')

        computed_key = ECIES::Crypt.new(kdf_shared_info: shared_info).kdf(shared_secret, expected_key.size)

        expect(computed_key).to eq expected_key
      end
    end

    it 'raises when size is invalid' do
      expect{ ECIES::Crypt.new.kdf('a', -1) }.to raise_error(RuntimeError)
      expect{ ECIES::Crypt.new.kdf('a', 32 * 2**32) }.to raise_error(RuntimeError)
    end
  end

end
