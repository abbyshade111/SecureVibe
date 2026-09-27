class NotesController < ApplicationController
  def search
    Note.where("t = '#{params[:q]}'")
  end
end
