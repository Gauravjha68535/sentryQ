# POSITIVE: Ruby injection vulnerabilities
require 'sinatra'

get '/user' do
  # Unsafe: ActiveRecord with params interpolation
  User.where("id = #{params[:id]}")
  User.find_by_sql("SELECT * FROM users WHERE id = #{params[:user_id]}")
  
  # Unsafe: shell with params
  system("ls #{params[:dir]}")
  
  # Unsafe: ERB with params
  ERB.new(params[:template]).result
end
