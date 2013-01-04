require 'pgp/cli'

module PGP
  # Currently, this is pretty quick-and-dirty. I should expand options into accessor methods, I know.
  class CLI
    module Runner

      def self.go!(args)
        cli = parse_args!(args)
        cli.run!
      end

      def self.parse_args!(args)
        cli = PGP::CLI.new

        cli.opt_parser = OptionParser.new do |opts|
          opts.banner = "Usage: jrpgp [options] file [file2] [file3] [...]"

          opts.on("-e", "--encrypt", "Perform Encryption") do
            cli[:action] = :encrypt
          end

          opts.on("-d", "--decrypt", "Perform Decryption") do
            cli[:action] = :decrypt
          end

          opts.on("-p", "--pub-key [file]", String, "The file containing Public Key(s) to encrypt to") do |fi|
            PGP::CLI.ensure_file_exists!(fi)
            cli[:public_keys] << fi
          end

          opts.on("-P", "--priv-key [file]", String, "The file containing Private Key(s) to use for decryption / signing") do |fi|
            PGP::CLI.ensure_file_exists!(fi)
            cli[:private_keys] << fi
          end

          opts.on("-i", "--in [file]", String, "The file to encrypt/decrypt") do |fi|
            PGP::CLI.ensure_file_exists!(fi)
            cli[:input_files] << fi
          end

          opts.on("-o", "--out [file]", String, "The file to output") do |fi|
            cli[:output_files] << fi
          end

          opts.on("-O", "--out-dir [dir]", String, "The directory where output files should be written") do |dir|
            PGP::CLI.ensure_dir_exists!(dir)
            cli[:outdir] = Pathname(dir).expand_path
          end

          opts.separator ""

          opts.on_tail("-h", "--help", "Show this message") do
            puts opts
            exit
          end

          # Another typical switch to print the version.
          opts.on_tail("--version", "Show version") do
            puts PGP::VERSION.join('.')
            exit
          end
        end

        cli.opt_parser.parse!(args)

        args.each do |file|
          PGP::CLI.ensure_file_exists!(file)
          cli[:input_files] << file
        end

        cli
      end

    end
  end
end

