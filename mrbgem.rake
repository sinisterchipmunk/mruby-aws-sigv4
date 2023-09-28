MRuby::Gem::Specification.new('mruby-aws-sigv4') do |spec|
  spec.license = 'MIT'
  spec.authors = 'sinisterchipmunk@gmail.com'
  spec.version = "0.0.1"

  sigv4_src = "#{spec.dir}/aws-sigv4"
  spec.cc.include_paths << "#{sigv4_src}/source/include"
  spec.cc.defines << 'SIGV4_DO_NOT_USE_CUSTOM_CONFIG'
  spec.cc.defines << 'SIGV4_PROCESSING_BUFFER_LENGTH=2048U'
  srcs = Dir.glob("#{sigv4_src}/source/*.c")
  spec.objs += srcs.map { |f| f.relative_path_from(dir).pathmap("#{build_dir}/%X.o") }

  spec.add_test_dependency 'mruby-print'
  spec.add_dependency 'mruby-digest'
  spec.add_dependency 'mruby-time'
  spec.add_dependency 'mruby-sprintf'
end
