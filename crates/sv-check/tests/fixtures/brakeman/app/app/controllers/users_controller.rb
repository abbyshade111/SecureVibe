class UsersController < ApplicationController
  skip_before_action :verify_authenticity_token

  def show
    @user = User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
  end

  def search
    @users = User.where("name LIKE '%#{params[:q]}%'")
  end

  def run
    system("ls #{params[:dir]}")
    @out = `cat #{params[:f]}`
  end

  def file
    send_file params[:path]
    File.read(params[:name])
  end

  def go
    redirect_to params[:url]
  end

  def load
    @obj = Marshal.load(params[:blob])
    @y = YAML.load(params[:doc])
  end

  def calc
    @r = eval(params[:expr])
  end

  def create
    @user = User.new(params[:user].permit!)
    User.create(params[:user])
  end

  def page
    render inline: params[:tpl]
    render params[:view]
  end

  def digest
    @d = Digest::MD5.hexdigest(params[:pw])
  end

  def fetch
    http = Net::HTTP.new("api.example.test", 443)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  end

  def reflect
    klass = params[:klass].constantize
    @user.send(params[:m])
  end

  def match
    @m = Regexp.new(params[:re]).match("x")
  end

  def crypt
    key = OpenSSL::PKey::RSA.new(1024)
    @c = key.public_encrypt(params[:data], OpenSSL::PKey::RSA::PKCS1_PADDING)
  end
end
