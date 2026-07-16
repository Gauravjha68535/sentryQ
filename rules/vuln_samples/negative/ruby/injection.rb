# NEGATIVE: Safe Ruby patterns
require 'sinatra'

get '/user' do
  id = params[:id]
  
  # Safe: parameterized ActiveRecord
  User.where("id = ?", id)
  User.where(id: id)
  
  # Safe: Shellwords escape
  require 'shellwords'
  safe_dir = Shellwords.escape(params[:dir])
  system("ls", params[:dir])
end
