require 'pgp'

module PGP
  # Currently, this is pretty quick-and-dirty. I should expand options into accessor methods, I know.
  class CLI
    autoload :Runner, 'pgp/cli/runner'

    attr_accessor :options, :opt_parser

    Encrypted_Extension_Regexp = /\.(pgp|gpg|asc)$/i

    def self.ensure_file_exists!(file)
      raise "The file #{file.inspect} does not appear to exist!" unless File.exist?(file)
    end

    def self.ensure_dir_exists!(dir)
      raise "The directory #{dir.inspect} does not appear to exist!" unless File.directory?(dir)
    end

    def initialize
      self.options = {
        :public_keys  => [],
        :private_keys => [],
        :input_files  => [],
        :output_files => [],
        :outdir       => Pathname(Dir.pwd),
        :same_dir     => false,
        :action       => nil,
        :signature    => false, # We do not currently support signing or verifying signatures
      }
    end

    def [](arg)
      options[arg]
    end

    def []=(arg, val)
      options[arg] = val
    end

    def validate_options!
      raise "Input file(s) must be specified!" if input_files.none?

      case action
      when :encrypt then validate_encrypt_options!
      when :decrypt then validate_decrypt_options!
      else
        raise "Valid actions are encrypt or decrypt. Action specified: #{options[:action]}"
      end

    rescue RuntimeError => e
      $stderr.puts opt_parser
      raise e
    end

    def run!
      validate_options!

      case options[:action]
      when :encrypt then encrypt!
      when :decrypt then decrypt!
      end
    end

    def encrypt!
      cryptor = Encryptor.new

      public_keys.each {|pub| cryptor.add_keys_from_file(pub) }

      input_files.each_with_index do |infile, idx|
        outfile = output_files[idx]
        output  = cryptor.encrypt_file(infile)

        File.open(outfile, "w") do |fi|
          fi.write output
        end
      end
    end

    def decrypt!
      cryptor = Decryptor.new

      private_keys.each {|priv| cryptor.add_keys_from_file(priv) }

      input_files.each_with_index do |infile, idx|
        outfile = output_files[idx]
        output  = cryptor.decrypt_file(infile)

        File.open(outfile, "w") do |fi|
          fi.write output
        end
      end
    end

    def action
      options[:action] ||= begin
        if input_files.grep(Encrypted_Extension_Regexp).any?
          :decrypt
        else
          :encrypt
        end
      end
    end

    def public_keys
      options[:public_keys]
    end

    def private_keys
      options[:private_keys]
    end

    def input_files
      options[:input_files]
    end

    def output_files
      options[:output_files]
    end

    def outdir
      options[:outdir]
    end

    def same_dir?
      options[:same_dir]
    end

    protected
    def set_outfile_dir(file)
      return file if same_dir?
      outdir + File.basename(file)
    end

    def validate_encrypt_options!
      raise "Public Keys are required for encryption"     if options[:public_keys].none?
      raise "Private Keys are required for signing files" if options[:signature] and options[:private_keys].none?

      options[:input_files].each_with_index do |infile, idx|
        next if options[:output_files][idx]
        options[:output_files][idx] = set_outfile_dir("#{infile}.gpg")
      end
    end

    def validate_decrypt_options!
      raise "Private Keys are required for decryption"          if options[:private_keys].none?
      raise "Public Keys are required for verifying signatures" if options[:signature] and options[:public_keys].none?

      options[:input_files].each_with_index do |infile, idx|
        next if options[:output_files][idx]

        outfile = infile.gsub(Encrypted_Extension_Regexp, '')
        outfile = "#{infile} - decrypted" if outfile == infile

        options[:output_files][idx] = set_outfile_dir(outfile)
      end
    end

  end
end
