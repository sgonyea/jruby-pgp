module PGP
  class PublicKey

    def self.from_file(path)
      self.new(File.read path)
    end

    def initialize(key)
      # @todo ...
    end

  end
end
