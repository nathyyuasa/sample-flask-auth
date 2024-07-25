from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user,login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
#view login
login_manager.login_view = 'login' #Setando a funcao
#Session <- conexao ativa

@login_manager.user_loader #Essa funcao Vai recuperar o objeto cadastrado no banco de dandos
def load_user(user_id):
     return User.query.get(user_id)

@app.route('/login',methods=["POST"])
#recomendado utilizar o POST por lidar com senhas e tambem para pode recuperar a senha
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        # login
        user = User.query.filter_by(username=username).first() #fazendo a verificacao do user no cadastro fisrt por ser unico

        if user and user.password == password:
                login_user(user)
                print(current_user.is_authenticated)
                return jsonify({"message": "Autenticacao realizada com sucesso"})

    return jsonify({"message": "Credenciais invalidas"}),400

@app.route('/user', methods=["POST"])
def create_user():
     data = request.json
     username = data.get("username")
     password = data.get("password")

     if  username and password:
          user = User(username=username, password=password)
          db.session.add(user)
          db.session.commit()
          return jsonify({"message": "Usuario cadastrado com sucesso"})
     
     return jsonify({"message": "Dados invalidos"}),400


@app.route('/logout',methods=['GET'])
@login_required
def logout():
     logout_user()
     return jsonify({"message": "Logout realizado com sucesso!"})


@app.route('/user/<int:id_user>', methods=["GET"])
@login_required
def read_user(id_user):
     user = User.query.get(id_user)

     if user:
          return {"username": user.username}
     return jsonify({"message": "Usuario nao encontrado"}),404


@app.route('/user/<int:id_user>', methods=["PUT"])
@login_required
def update_user(id_user):
     data = request.json #Recuperar os dados
     user = User.query.get(id_user)

     if user and data.get("password"): 
          user.password = data.get("password") # recuperar a senha
          db.session.commit() #Sempre colocar o commit senao pode nao atualizar a informacao no banco de dados
          
          return jsonify({"message": f"Usuario {id_user} atualizado com sucesso!"})
     
     return jsonify({"message": "Usuario nao encontrado"}),404


@app.route('/user/<int:id_user>', methods=["DELETE"])
@login_required
def delete_user(id_user):
     user = User.query.get(id_user)

     
     if id_user == current_user.id: # Essa condicao ira verificar se o usuario nao esta tentando deletar a conta em que esta autenticado
          return jsonify({"message": "Delecao nao permitida"}),403
          
     if user: #diferente(!=)
            db.session.delete(user)
            db.session.commit()
            return jsonify({"message": f"Usuario {id_user} deletado com sucesso!"})
     
     return jsonify({"message": "Usuario nao encontrado"}),404
     

if __name__ == '__main__':
    app.run(debug=True)