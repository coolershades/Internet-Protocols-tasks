import json

with open('config.json', 'r') as file:
    config_data = json.load(file)
    app_id = config_data['app_id']

# 1026 из ссылки ниже- доступ к друзьям и статусу
get_access_token_url = f'https://oauth.vk.com/authorize?client_id={app_id}&display=page&redirect_uri=&scope={1026}&response_type=token&v=5.131&state=123456'
print(get_access_token_url)