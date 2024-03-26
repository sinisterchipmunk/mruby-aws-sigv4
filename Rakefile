unless defined?(MRuby)
  repository, dir = 'https://github.com/mruby/mruby.git', 'tmp/mruby'
  build_args = ARGV

  Dir.mkdir 'tmp'  unless File.exist?('tmp')
  unless File.exist?(dir)
    system "git clone #{repository} #{dir}"
  end

  exit system(%Q[cd #{dir}; MRUBY_CONFIG=#{File.expand_path __FILE__} rake #{build_args.join(' ')}])
end

MRuby::Build.new do |conf|
  toolchain :clang
  conf.enable_sanitizer "address,undefined"
  conf.gembox 'full-core'
  conf.gem File.expand_path(File.dirname(__FILE__)) do |g|
    g.cc.defines.delete 'SIGV4_DO_NOT_USE_CUSTOM_CONFIG'
    g.add_dependency 'mruby-digest'
  end
  conf.enable_test
  conf.enable_debug
  conf.disable_lock
end
