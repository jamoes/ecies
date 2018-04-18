task 'default' => 'spec'

desc 'Run specs'
task 'spec' do
  sh 'rspec'
end

desc 'Run specs and generate coverage report'
task 'coverage' do
  ENV['COVERAGE'] = 'Y'
  Rake::Task['spec'].invoke
end

desc 'Print out lines of code and related statistics.'
task 'stats' do
  puts 'Lines of code and comments (including blank lines):'
  sh "find lib -type f | xargs wc -l"
  puts "\nLines of code (excluding comments and blank lines):"
  sh "find lib -type f | xargs cat | sed '/^\s*#/d;/^\s*$/d' | wc -l"
end

desc 'Generate documentation'
task 'doc' do
  sh 'yardoc'
end
