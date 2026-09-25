Rails.application.routes.draw do
  get "users/:id" => "users#show"
  get "search" => "users#search"
  get "run" => "users#run"
  get "file" => "users#file"
  get "go" => "users#go"
  post "load" => "users#load"
  get "calc" => "users#calc"
  post "create" => "users#create"
  get "page" => "users#page"
end
