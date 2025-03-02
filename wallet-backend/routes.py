from flask import Blueprint
from flask_cors import CORS
from services import WalletService

wallet_routes = Blueprint('praavi_wallet_routes', __name__)
CORS(wallet_routes)

wallet_routes.add_url_rule('/register', "register", view_func=WalletService.register, methods=['POST'])
wallet_routes.add_url_rule('/login', "login", view_func=WalletService.login, methods=['POST'])
wallet_routes.add_url_rule('/get-wallet-balance', "get_wallet_balance", view_func=WalletService.get_wallet_balance, methods=['GET'])
wallet_routes.add_url_rule('/add-money', "add_money",view_func=WalletService().add_money, methods=['POST'])
wallet_routes.add_url_rule('/get-all-users', "get_all_users",view_func=WalletService().get_all_users, methods=['GET'])
wallet_routes.add_url_rule('/add-employees', "add_employees",view_func=WalletService().add_employees, methods=['POST'])
wallet_routes.add_url_rule('/my-employees', "my_employees",view_func=WalletService().get_my_employees, methods=['GET'])
wallet_routes.add_url_rule('/assign-wallet', "assign_wallet",view_func=WalletService().assign_wallet, methods=['POST'])
wallet_routes.add_url_rule('/my-wallet-employees', "my_wallet_employees",view_func=WalletService().get_my_wallet_employees, methods=['GET'])
wallet_routes.add_url_rule('/wallet-transaction', "wallet_transaction", view_func=WalletService().wallet_transaction, methods=['POST'])