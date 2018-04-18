module ECIES
  # Provides functionality for encrypting and decrypting messages using ECIES.
  # Encapsulates the configuration parameters chosen for ECIES.
  class Crypt

    # The allowed digest algorithms for ECIES.
    DIGESTS = %w{SHA224 SHA256 SHA384 SHA512}

    # The allowed cipher algorithms for ECIES.
    CIPHERS = %w{AES-128-CBC AES-192-CBC AES-256-CBC AES-128-CTR AES-192-CTR AES-256-CTR}

    # The initialization vector used in ECIES. Quoting from sec1-v2:
    # "When using ECIES, some exception are made. For the CBC and CTR modes, the
    # initial value or initial counter are set to be zero and are omitted from
    # the ciphertext. In general this practice is not advisable, but in the case
    # of ECIES it is acceptable because the definition of ECIES implies the
    # symmetric block cipher key is only to be used once.
    IV = ("\x00" * 16).force_encoding(Encoding::BINARY)

    # Creates a new instance of {Crypt}.
    #
    # @param cipher [String] The cipher algorithm to use. Must be one of
    #     {CIPHERS}.
    # @param digest [String,OpenSSL::Digest] The digest algorithm to use for
    #     HMAC and KDF. Must be one of {DIGESTS}.
    # @param mac_length [:half,:full] The length of the mac. If :half, the mac
    #     length will be equal to half the mac_digest's digest_legnth. If
    #     :full, the mac length will be equal to the mac_digest's
    #     digest_length.
    # @param kdf_digest [String,OpenSSL::Digest,nil] The digest algorithm to
    #     use for KDF. If not specified, the `digest` argument will be used.
    # @param mac_digest [String,OpenSSL::Digest,nil] The digest algorithm to
    #     use for HMAC. If not specified, the `digest` argument will be used.
    # @param kdf_shared_info [String] Optional. A string containing the shared
    #     info used for KDF, also known as SharedInfo1.
    # @param mac_shared_info [String] Optional. A string containing the shared
    #     info used for MAC, also known as SharedInfo2.
    def initialize(cipher: 'AES-256-CTR', digest: 'SHA256', mac_length: :half, kdf_digest: nil, mac_digest: nil, kdf_shared_info: '', mac_shared_info: '')
      @cipher = OpenSSL::Cipher.new(cipher)
      @mac_digest = OpenSSL::Digest.new(mac_digest || digest)
      @kdf_digest = OpenSSL::Digest.new(kdf_digest || digest)
      @kdf_shared_info = kdf_shared_info
      @mac_shared_info = mac_shared_info

      CIPHERS.include?(@cipher.name) or raise "Cipher must be one of #{CIPHERS}"
      DIGESTS.include?(@mac_digest.name) or raise "Digest must be one of #{DIGESTS}"
      DIGESTS.include?(@kdf_digest.name) or raise "Digest must be one of #{DIGESTS}"
      [:half, :full].include?(mac_length) or raise "mac_length must be :half or :full"

      @mac_length = @mac_digest.digest_length
      @mac_length /= 2 if mac_length == :half
    end

    # Encrypts a message to a public key using ECIES.
    #
    # # @param key [OpenSSL::EC:PKey] The public key.
    # @param message [String] The plain-text message.
    # @return [String] The octet string of the encrypted message.
    def encrypt(key, message)
      key.public_key? or raise "Must have public key to encrypt"
      @cipher.reset

      group_copy = OpenSSL::PKey::EC::Group.new(key.group)
      group_copy.point_conversion_form = :compressed
      ephemeral_key = OpenSSL::PKey::EC.new(group_copy).generate_key

      shared_secret = ephemeral_key.dh_compute_key(key.public_key)

      key_pair = kdf(shared_secret, @cipher.key_len + @mac_length)
      cipher_key = key_pair.byteslice(0, @cipher.key_len)
      hmac_key = key_pair.byteslice(-@mac_length, @mac_length)

      @cipher.encrypt
      @cipher.iv = IV
      @cipher.key = cipher_key
      ciphertext = @cipher.update(message) + @cipher.final

      mac = OpenSSL::HMAC.digest(@mac_digest, hmac_key, ciphertext + @mac_shared_info).byteslice(0, @mac_length)

      ephemeral_key.public_key.to_bn.to_s(2) + ciphertext + mac
    end

    # Decrypts a message with a private key using ECIES.
    #
    # @param key [OpenSSL::EC:PKey] The private key.
    # @param encrypted_message [String] Octet string of the encrypted message.
    # @return [String] The plain-text message.
    def decrypt(key, encrypted_message)
      key.private_key? or raise "Must have private key to decrypt"
      @cipher.reset

      group_copy = OpenSSL::PKey::EC::Group.new(key.group)
      group_copy.point_conversion_form = :compressed

      ephemeral_public_key_length = group_copy.generator.to_bn.to_s(2).bytesize
      ciphertext_length = encrypted_message.bytesize - ephemeral_public_key_length - @mac_length
      ciphertext_length > 0 or raise OpenSSL::PKey::ECError, "Encrypted message too short"

      ephemeral_public_key_text = encrypted_message.byteslice(0, ephemeral_public_key_length)
      ciphertext = encrypted_message.byteslice(ephemeral_public_key_length, ciphertext_length)
      mac = encrypted_message.byteslice(-@mac_length, @mac_length)

      ephemeral_public_key = OpenSSL::PKey::EC::Point.new(group_copy, OpenSSL::BN.new(ephemeral_public_key_text, 2))

      shared_secret = key.dh_compute_key(ephemeral_public_key)

      key_pair = kdf(shared_secret, @cipher.key_len + @mac_length)
      cipher_key = key_pair.byteslice(0, @cipher.key_len)
      hmac_key = key_pair.byteslice(-@mac_length, @mac_length)

      computed_mac = OpenSSL::HMAC.digest(@mac_digest, hmac_key, ciphertext + @mac_shared_info).byteslice(0, @mac_length)
      computed_mac == mac or raise OpenSSL::PKey::ECError, "Invalid Message Authenticaton Code"

      @cipher.decrypt
      @cipher.iv = IV
      @cipher.key = cipher_key

      @cipher.update(ciphertext) + @cipher.final
    end

    # Key-derivation function, compatible with ANSI-X9.63-KDF
    #
    # @param shared_secret [String] The shared secret from which the key will be
    #     derived.
    # @param length [Integer] The length of the key to generate.
    # @return [String] Octet string of the derived key.
    def kdf(shared_secret, length)
      length >=0 or raise "length cannot be negative"
      return "" if length == 0

      if length / @kdf_digest.digest_length >= 0xFF_FF_FF_FF
        raise "length too large"
      end

      io = StringIO.new(String.new)
      counter = 0

      loop do
        counter += 1
        counter_bytes = [counter].pack('N')

        io << @kdf_digest.digest(shared_secret + counter_bytes + @kdf_shared_info)
        if io.pos >= length
          return io.string.byteslice(0, length)
        end
      end
    end
  end
end
