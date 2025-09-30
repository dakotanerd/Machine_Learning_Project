# legacy_script.rb
# Ruby insecure sample for training
# Issues: eval on user input, system call constructed from input, hardcoded file path for secrets

def run_cmd(cmd)
  # Danger: constructing system commands from user input
  system(cmd)
end

def insecure_eval(code)
  # Danger: evaluating arbitrary Ruby code
  eval(code)
end

def read_secret()
  # Hardcoded path and naive read
  path = "/etc/app/secret.txt"
  if File.exists?(path)
    return File.read(path).strip
  else
    return "nofile"
  end
end

if __FILE__ == $0
  puts "Enter command:"
  cmd = gets.chomp
  run_cmd(cmd)  # unsafe

  puts "Enter code to eval:"
  code = gets.chomp
  insecure_eval(code)  # unsafe

  puts "Secret: #{read_secret()}"
end
