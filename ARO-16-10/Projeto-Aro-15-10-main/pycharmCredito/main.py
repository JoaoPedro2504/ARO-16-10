
from flask import Flask, render_template, request, flash, redirect, url_for, session

import fdb
from datetime import date

from flask_bcrypt import Bcrypt

# CONFIGURAÇÃO DO FLASK
app = Flask(__name__, template_folder="Templates")
bcrypt = Bcrypt(app)
app.config["SECRET_KEY"] = "Chavesdfglkjhgfdshjkjhgfdcvbmnb"
# CONEXÃO COM O BANCO
host = "localhost"
database = r"C:\Users\Aluno\Downloads\ARO-100--main\ARO-100--main\Projeto-Aro-15-10-main\BANCO-ARO-CREDITO-FINAL\BANCO.FDB"
user = "SYSDBA"
password = "sysdba"

con = fdb.connect(
    host=host,
    database=database,
    user=user,
    password=password
)

# VERIFICAÇÃO DE SENHA FORTE

def senha_forte(senha):
    if len(senha) < 8 :
        return False

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_simbolo = False

    # Verifica cada caractere da senha.
    for caractere in senha:
        if caractere.isupper():
            tem_maiuscula = True
        if caractere.islower():
            tem_minuscula = True
        if caractere.isdigit():
            tem_numero = True
        if caractere in "!@#%":
            tem_simbolo = True
        if caractere.isspace():
            return False

    if tem_maiuscula and tem_minuscula and tem_numero and tem_simbolo:
        return True
    else:
        return False


# VERIFICA A SENHA CRIPTOGRAFADA

def verificar_senha(senha_hash, senha):
    return bcrypt.check_password_hash(senha_hash, senha)

# VERIFICA SE O USUÁRIO ESTÁ AUTENTICADO

def usuario_autenticado():
    if "id_usuario" not in session:
        return False

    cursor = con.cursor()
    try:
        # Consulta somente a conta que está na sessão.
        cursor.execute("""SELECT ATIVO, BLOQUEADO_LOGIN FROM USUARIO
                          WHERE ID_USUARIO = ?""", (session["id_usuario"],))
        usuario = cursor.fetchone()
        con.commit()

        if usuario:
            if usuario[0] == 1 and usuario[1] == 0:
                return True

        return False
    except Exception:
        con.rollback()
        return False
    finally:
        con.rollback()
        cursor.close()

# PÁGINA INICIAL DO SITE

@app.route("/")
def landing():
    return render_template("landing.html")

# PÁGINA DO USUÁRIO LOGADO

@app.route("/novo")
def novo():
    if not usuario_autenticado():
        session.clear()

        flash("Precisa estar logado e ativo!", "error")

        return redirect(url_for("login"))

    if "nome_usuario" not in session:
        session.clear()

        flash("Faça login novamente!", "error")

        return redirect(url_for("login"))

    return render_template("inicio.html", usuario=session["nome_usuario"])

# PÁGINA DE CADASTRO

@app.route("/cadastro")
def pagina_cadastro():
    return render_template("cadastro.html")

# CADASTRAR USUÁRIO

@app.route("/cadastro", methods=["POST"])
def cadastro():
    nome = request.form.get("nome", "").strip()

    email = request.form.get("email", "").strip()

    senha = request.form.get("senha", "")

    confirmar_senha = request.form.get("confirmar_senha", "")

    receita_mensal = request.form.get("renda_mensal", "").strip()

    despesa_mensal = request.form.get("despesas_mensal", "").strip()

    tipo_usuario = 7

    if not nome or not email or not senha or not confirmar_senha or not receita_mensal or not despesa_mensal:
        flash("Preencha todos os campos!", "error")

        return redirect(url_for("pagina_cadastro"))

    if senha != confirmar_senha:
        flash("A senha e a confirmação de senha não são iguais!", "error")

        return redirect(url_for("pagina_cadastro"))

    if not senha_forte(senha):
        flash(
            "A senha deve ter pelo menos 8 caracteres, letras maiúsculas, minúsculas, números e um símbolo (! @ # %) e sem espaços. ",
            "error"
        )

        return redirect(url_for("pagina_cadastro"))

    cursor = con.cursor()

    try:
        # VERIFICA E-MAIL REPETIDO

        cursor.execute("""SELECT ID_USUARIO FROM USUARIO WHERE UPPER(EMAIL) = UPPER(?)""", (email,))

        if cursor.fetchone():
            flash("Este e-mail já está cadastrado!", "error")

            return redirect(url_for("pagina_cadastro"))

        # CONVERTE RENDA E DESPESAS

        receita_mensal = float(receita_mensal)

        despesa_mensal = float(despesa_mensal)

        # Impede renda ou despesas negativas.

        if receita_mensal < 0 or despesa_mensal < 0:
            flash("Os valores não podem ser negativos!", "error")

            return redirect(url_for("pagina_cadastro"))

        # CRIPTOGRAFA A SENHA

        try:
            senha_hash = bcrypt.generate_password_hash(senha).decode("utf-8")
        except ValueError:
            flash("A senha é muito longa para o Bcrypt.", "error")
            return redirect(url_for("pagina_cadastro"))

        # SALVA O USUÁRIO NO BANCO

        cursor.execute("""INSERT INTO USUARIO (NOME, EMAIL, SENHA, RECEITA_MENSAL, DESPESA_MENSAL, TIPO_USUARIO) VALUES (?, ?, ?, ?, ?, ?)""", (
            nome,
            email,
            senha_hash,
            receita_mensal,
            despesa_mensal,
            tipo_usuario
        ))

        con.commit()

        flash("Cadastro realizado com sucesso!", "success")

        return redirect(url_for("login"))

    except ValueError:
        con.rollback()

        flash("Digite valores válidos para renda e despesas.", "error")

        return redirect(url_for("pagina_cadastro"))

    except Exception as e:
        con.rollback()

        flash(f"Erro ao cadastrar: {e}", "error")

        return redirect(url_for("pagina_cadastro"))

    finally:
        con.rollback()
        cursor.close()

# PÁGINA DE LOGIN

@app.route("/login")
def login():
    return render_template("login.html")

# ENTRAR NA CONTA

@app.route("/login", methods=["POST"])
def entrar_usuario():
    email = request.form.get("email", "").strip()

    senha = request.form.get("senha", "")

    if not email or not senha:
        flash("Preencha o e-mail e a senha!", "error")
        return redirect(url_for("login"))

    cursor = con.cursor()
    try:
        # Busca os dados e as tentativas da conta informada.
        cursor.execute("""SELECT ID_USUARIO, NOME, SENHA, ATIVO,
                          TENTATIVAS_LOGIN, BLOQUEADO_LOGIN
                          FROM USUARIO WHERE UPPER(EMAIL) = UPPER(?)""", (email,))
        usuario = cursor.fetchone()

        if not usuario:
            flash("E-mail ou senha incorretos!", "error")
            return redirect(url_for("login"))

        id_usuario, nome, senha_hash, ativo, tentativas, bloqueado = usuario

        if ativo != 1:
            flash("Usuário inativo!", "error")
            return redirect(url_for("login"))

        if bloqueado == 1 or tentativas >= 3:
            flash("Usuário bloqueado! Solicite o desbloqueio.", "error")
            return redirect(url_for("login"))

        # Se acertar a senha, zera apenas as tentativas desta conta.
        if verificar_senha(senha_hash, senha):
            cursor.execute("""UPDATE USUARIO SET TENTATIVAS_LOGIN = 0
                              WHERE ID_USUARIO = ?""", (id_usuario,))
            con.commit()

            session.clear()
            session["id_usuario"] = id_usuario
            session["nome_usuario"] = nome
            flash("Login realizado com sucesso!", "success")
            return redirect(url_for("novo"))

        # Se errar a senha, soma uma tentativa.
        tentativas = tentativas + 1

        if tentativas >= 3:
            bloqueado = 1
            flash("Usuário bloqueado após 3 tentativas!", "error")
        else:
            flash(f"Senha incorreta! Restam {3 - tentativas} tentativa(s).", "error")

        # O ID no WHERE garante que somente esta conta será alterada.
        cursor.execute("""UPDATE USUARIO
                          SET TENTATIVAS_LOGIN = ?, BLOQUEADO_LOGIN = ?
                          WHERE ID_USUARIO = ?""", (tentativas, bloqueado, id_usuario))
        con.commit()
        return redirect(url_for("login"))

    except Exception:
        con.rollback()
        flash("Não foi possível entrar. Verifique a conexão com o banco.", "error")
        return redirect(url_for("login"))
    finally:
        # Encerra a consulta, inclusive quando o login é recusado.
        con.rollback()
        cursor.close()

# LOGOUT

@app.route("/logout", methods=["POST"])
def logout():
    if "id_usuario" not in session:
        flash("Precisa estar logado!", "error")

        return redirect(url_for("login"))

    session.clear()

    flash("Você saiu da sua conta!", "success")

    return redirect(url_for("login"))

# EDITAR USUÁRIO

@app.route("/editar_usuario")
def editar_usuario():
    if not usuario_autenticado():
        session.clear()

        flash("Precisa estar logado e ativo!", "error")

        return redirect(url_for("login"))

    cursor = con.cursor()
    try:
        cursor.execute("""SELECT ID_USUARIO, NOME, EMAIL, RECEITA_MENSAL, DESPESA_MENSAL, TIPO_USUARIO FROM USUARIO WHERE ID_USUARIO = ?""", (session["id_usuario"],))

        usuario = cursor.fetchone()

        if not usuario:
            session.clear()

            flash("Usuário não encontrado!", "error")

            return redirect(url_for("login"))

        return render_template("editar_usuario.html", usuario=usuario)
    finally:
        con.rollback()
        cursor.close()

# SALVAR EDIÇÃO DO USUÁRIO

@app.route("/salvar_edicao", methods=["POST"])
def salvar_edicao():
    if not usuario_autenticado():
        session.clear()

        flash("Precisa estar logado e ativo!", "error")

        return redirect(url_for("login"))

    nome = request.form.get("nome", "").strip()

    email = request.form.get("email", "").strip()

    senha = request.form.get("senha", "")

    confirmar_senha = request.form.get("confirmar_senha", "")

    receita_mensal = request.form.get("renda_mensal", "").strip()

    despesa_mensal = request.form.get("despesas_mensal", "").strip()

    if not nome or not email or not receita_mensal or not despesa_mensal:
        flash("Preencha todos os campos!", "error")

        return redirect(url_for("editar_usuario"))

    if senha != confirmar_senha:
        flash("A nova senha e a confirmação não são iguais!", "error")

        return redirect(url_for("editar_usuario"))

    if senha and not senha_forte(senha):
        flash(
            "A nova senha deve ter pelo menos 8 caracteres, letras maiúsculas, minúsculas, números e um símbolo (! @ # %), sem espaços e com até 72 bytes em UTF-8.",
            "error")

        return redirect(url_for("editar_usuario"))

    cursor = con.cursor()
    try:
        # VERIFICA E-MAIL REPETIDO

        cursor.execute("""SELECT ID_USUARIO FROM USUARIO WHERE UPPER(EMAIL) = UPPER(?) AND ID_USUARIO <> ?""", (email, session["id_usuario"]))

        if cursor.fetchone():
            flash("Este e-mail já está cadastrado!", "error")

            return redirect(url_for("editar_usuario"))

        # CONVERTE RENDA E DESPESAS

        receita_mensal = float(receita_mensal)

        despesa_mensal = float(despesa_mensal)



        if receita_mensal < 0 or despesa_mensal < 0:
            flash("Os valores não podem ser negativos!", "error")

            return redirect(url_for("editar_usuario"))

        # ATUALIZA OS DADOS

        if senha:
            cursor.execute("""SELECT SENHA, SENHA_ANTERIOR1, SENHA_ANTERIOR2, SENHA_ANTERIOR3 FROM USUARIO WHERE ID_USUARIO = ?""", (session["id_usuario"],))

            dados = cursor.fetchone()

            if not dados:
                session.clear()

                flash("Usuário não encontrado!", "error")

                return redirect(url_for("login"))

            # VERIFICA AS SENHAS ANTERIORES

            for senha_antiga in dados:
                if senha_antiga:
                    if verificar_senha(senha_antiga, senha):
                        flash(
                            "Você não pode reutilizar a senha atual nem as 3 anteriores!",
                            "error"
                        )

                        return redirect(url_for("editar_usuario"))

            # CRIPTOGRAFA A NOVA SENHA

            try:
                senha_hash = bcrypt.generate_password_hash(senha).decode("utf-8")
            except ValueError:
                flash("A senha é muito longa para o Bcrypt.", "error")
                return redirect(url_for("editar_usuario"))

            # ATUALIZA OS DADOS E O HISTÓRICO

            cursor.execute("""UPDATE USUARIO SET NOME = ?, EMAIL = ?, SENHA_ANTERIOR3 = SENHA_ANTERIOR2, SENHA_ANTERIOR2 = SENHA_ANTERIOR1, SENHA_ANTERIOR1 = SENHA, SENHA = ?, RECEITA_MENSAL = ?, DESPESA_MENSAL = ? WHERE ID_USUARIO = ?""", (
                nome,
                email,
                senha_hash,
                receita_mensal,
                despesa_mensal,
                session["id_usuario"]
            ))

        else:
            cursor.execute("""UPDATE USUARIO SET NOME = ?, EMAIL = ?, RECEITA_MENSAL = ?, DESPESA_MENSAL = ? WHERE ID_USUARIO = ?""", (
                nome,
                email,
                receita_mensal,
                despesa_mensal,
                session["id_usuario"]
            ))

        # SALVA NO BANCO

        con.commit()

        session["nome_usuario"] = nome

        flash("Usuário atualizado com sucesso!", "success")

        return redirect(url_for("novo"))

    except ValueError:
        con.rollback()

        flash("Digite valores numéricos válidos!", "error")

        return redirect(url_for("editar_usuario"))

    except Exception as e:
        con.rollback()

        flash(f"Erro ao editar usuário: {e}", "error")

        return redirect(url_for("editar_usuario"))
    finally:
        con.rollback()
        cursor.close()

# SALDO ATUAL

@app.route("/saldo_atual")
def saldo_atual():
    if not usuario_autenticado():
        session.clear()
        flash("Faça login para acessar esta página!", "error")
        return redirect(url_for("login"))

    return render_template("saldo_atual.html")



# ==========================================
# RECEITAS, DESPESAS, SALDOS E TAXAS
# ==========================================

# Confere se o valor do formulario e um numero positivo.
def valor_positivo(texto):
    # So aceita numeros positivos com ate duas casas decimais.
    try:
        if not texto:
            return None

        pontos = 0
        casas = 0
        for caractere in texto:
            if caractere == ".":
                pontos = pontos + 1
                if pontos > 1:
                    return None
            elif caractere >= "0" and caractere <= "9":
                if pontos == 1:
                    casas = casas + 1
            else:
                return None

        if casas > 2 or texto[0] == "." or texto[-1] == ".":
            return None

        valor = float(texto)
        if valor > 0 and valor < 1000000000:
            return valor
    except ValueError:
        return None
    return None


# Verifica a data sem provocar erro de SQL no Firebird.
def conferir_data(cursor, texto):
    if len(texto) != 10 or texto[4] != "-" or texto[7] != "-":
        raise ValueError("Data invalida")

    for caractere in texto:
        if caractere != "-" and (caractere < "0" or caractere > "9"):
            raise ValueError("Data invalida")

    ano = int(texto[0:4])
    mes = int(texto[5:7])
    dia = int(texto[8:10])
    return date(ano, mes, dia)

# Atualiza o saldo do mes do usuario no proprio Firebird.
# A funcao deve ser chamada depois de incluir, editar ou excluir um movimento.
def atualizar_saldo_mensal(cursor, id_usuario, data):
    ano = data.year
    mes = data.month

    cursor.execute("""
        SELECT COALESCE(SUM(VALOR), 0) FROM RECEITA
        WHERE ID_USUARIO = ?
          AND EXTRACT(YEAR FROM DATA_RECEITA) = ?
          AND EXTRACT(MONTH FROM DATA_RECEITA) = ?
    """, (id_usuario, ano, mes))
    total_receitas = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COALESCE(SUM(VALOR), 0) FROM DESPESA
        WHERE ID_USUARIO = ?
          AND EXTRACT(YEAR FROM DATA_DESPESA) = ?
          AND EXTRACT(MONTH FROM DATA_DESPESA) = ?
    """, (id_usuario, ano, mes))
    total_despesas = cursor.fetchone()[0]

    saldo = total_receitas - total_despesas
    cursor.execute("""
        UPDATE OR INSERT INTO SALDO_MENSAL
        (ID_USUARIO, ANO, MES, TOTAL_RECEITAS, TOTAL_DESPESAS, SALDO)
        VALUES (?, ?, ?, ?, ?, ?)
        MATCHING (ID_USUARIO, ANO, MES)
    """, (id_usuario, ano, mes, total_receitas, total_despesas, saldo))


# Lista apenas os movimentos do usuario e prepara a edicao opcional.
@app.route("/receitas")
def pagina_receitas():
    if not usuario_autenticado():
        flash("Faça login para acessar esta página!", "error")
        return redirect(url_for("login"))

    cursor = con.cursor()
    try:
        id_edicao = request.args.get("editar", type=int)
        editar = None
        if id_edicao:
            cursor.execute("""
                SELECT ID_RECEITA, DESCRICAO, VALOR, DATA_RECEITA
                FROM RECEITA WHERE ID_RECEITA = ? AND ID_USUARIO = ?
            """, (id_edicao, session["id_usuario"]))
            editar = cursor.fetchone()
            if not editar:
                flash("Receita não encontrada.", "error")
                return redirect(url_for("pagina_receitas"))

        cursor.execute("""
            SELECT ID_RECEITA, DESCRICAO, VALOR, DATA_RECEITA
            FROM RECEITA WHERE ID_USUARIO = ?
            ORDER BY DATA_RECEITA DESC, ID_RECEITA DESC
        """, (session["id_usuario"],))
        registros = cursor.fetchall()
        return render_template("receitas.html", registros=registros, editar=editar)
    except Exception:
        flash("Erro ao listar receitas.", "error")
        return redirect(url_for("novo"))
    finally:
        con.rollback()
        cursor.close()


# Insere um movimento do usuario com valor positivo e data valida.
@app.route("/receitas/cadastrar", methods=["POST"])
def cadastrar_receita():
    if not usuario_autenticado():
        return redirect(url_for("login"))

    descricao = request.form.get("descricao", "").strip()
    valor = valor_positivo(request.form.get("valor", ""))
    data_texto = request.form.get("data", "")

    if not descricao or len(descricao) > 100 or valor is None:
        flash("Informe uma descrição e um valor positivo válido.", "error")
        return redirect(url_for("pagina_receitas"))

    cursor = con.cursor()
    try:
        data = conferir_data(cursor, data_texto)
        cursor.execute("""
            INSERT INTO RECEITA
            (ID_USUARIO, DESCRICAO, VALOR, DATA_RECEITA)
            VALUES (?, ?, ?, ?)
        """, (session["id_usuario"], descricao, valor, data))

        atualizar_saldo_mensal(cursor, session["id_usuario"], data)
        con.commit()
        flash("Receita cadastrada com sucesso!", "success")
    except ValueError:
        con.rollback()
        flash("Informe uma data válida.", "error")
    except Exception:
        con.rollback()
        flash("Não foi possível cadastrar. Verifique a data e os campos.", "error")
    finally:
        cursor.close()
    return redirect(url_for("pagina_receitas"))


# Edita somente um movimento que pertence ao usuario logado.
@app.route("/receitas/editar/<int:id_registro>", methods=["POST"])
def editar_receita(id_registro):
    if not usuario_autenticado():
        return redirect(url_for("login"))

    descricao = request.form.get("descricao", "").strip()
    valor = valor_positivo(request.form.get("valor", ""))
    data_texto = request.form.get("data", "")

    if not descricao or len(descricao) > 100 or valor is None:
        flash("Informe uma descrição e um valor positivo válido.", "error")
        return redirect(url_for("pagina_receitas"))

    cursor = con.cursor()
    try:
        cursor.execute("""
            SELECT DATA_RECEITA FROM RECEITA
            WHERE ID_RECEITA = ? AND ID_USUARIO = ?
        """, (id_registro, session["id_usuario"]))
        anterior = cursor.fetchone()
        if not anterior:
            flash("Receita não encontrada.", "error")
            return redirect(url_for("pagina_receitas"))

        nova_data = conferir_data(cursor, data_texto)
        cursor.execute("""
            UPDATE RECEITA SET DESCRICAO = ?, VALOR = ?, DATA_RECEITA = ?
            WHERE ID_RECEITA = ? AND ID_USUARIO = ?
        """, (descricao, valor, nova_data, id_registro, session["id_usuario"]))

        atualizar_saldo_mensal(cursor, session["id_usuario"], anterior[0])
        if anterior[0] != nova_data:
            atualizar_saldo_mensal(cursor, session["id_usuario"], nova_data)
        con.commit()
        flash("Receita atualizada com sucesso!", "success")
    except ValueError:
        con.rollback()
        flash("Informe uma data válida.", "error")
    except Exception:
        con.rollback()
        flash("Não foi possível editar. Verifique os dados.", "error")
    finally:
        cursor.close()
    return redirect(url_for("pagina_receitas"))


# Exclui somente o movimento pertencente ao usuario logado.
@app.route("/receitas/excluir/<int:id_registro>", methods=["POST"])
def excluir_receita(id_registro):
    if not usuario_autenticado():
        return redirect(url_for("login"))

    cursor = con.cursor()
    try:
        cursor.execute("""
            SELECT DATA_RECEITA FROM RECEITA
            WHERE ID_RECEITA = ? AND ID_USUARIO = ?
        """, (id_registro, session["id_usuario"]))
        anterior = cursor.fetchone()
        if not anterior:
            flash("Receita não encontrada.", "error")
            return redirect(url_for("pagina_receitas"))

        cursor.execute("""
            DELETE FROM RECEITA WHERE ID_RECEITA = ? AND ID_USUARIO = ?
        """, (id_registro, session["id_usuario"]))
        atualizar_saldo_mensal(cursor, session["id_usuario"], anterior[0])
        con.commit()
        flash("Receita excluída com sucesso!", "success")
    except Exception:
        con.rollback()
        flash("Não foi possível excluir a receita.", "error")
    finally:
        cursor.close()
    return redirect(url_for("pagina_receitas"))


# Lista apenas os movimentos do usuario e prepara a edicao opcional.
@app.route("/despesas")
def pagina_despesas():
    if not usuario_autenticado():
        flash("Faça login para acessar esta página!", "error")
        return redirect(url_for("login"))

    cursor = con.cursor()
    try:
        id_edicao = request.args.get("editar", type=int)
        editar = None
        if id_edicao:
            cursor.execute("""
                SELECT ID_DESPESA, DESCRICAO, VALOR, DATA_DESPESA, CLASSIFICACAO
                FROM DESPESA WHERE ID_DESPESA = ? AND ID_USUARIO = ?
            """, (id_edicao, session["id_usuario"]))
            editar = cursor.fetchone()
            if not editar:
                flash("Despesa não encontrada.", "error")
                return redirect(url_for("pagina_despesas"))

        cursor.execute("""
            SELECT ID_DESPESA, DESCRICAO, VALOR, DATA_DESPESA, CLASSIFICACAO
            FROM DESPESA WHERE ID_USUARIO = ?
            ORDER BY DATA_DESPESA DESC, ID_DESPESA DESC
        """, (session["id_usuario"],))
        registros = cursor.fetchall()
        return render_template("despesas.html", registros=registros, editar=editar)
    except Exception:
        flash("Erro ao listar despesas.", "error")
        return redirect(url_for("novo"))
    finally:
        con.rollback()
        cursor.close()


# Insere um movimento do usuario com valor positivo e data valida.
@app.route("/despesas/cadastrar", methods=["POST"])
def cadastrar_despesa():
    if not usuario_autenticado():
        return redirect(url_for("login"))

    descricao = request.form.get("descricao", "").strip()
    valor = valor_positivo(request.form.get("valor", ""))
    data_texto = request.form.get("data", "")

    classificacao = request.form.get("classificacao", "")
    if not descricao or len(descricao) > 100 or valor is None:
        flash("Informe uma descrição e um valor positivo válido.", "error")
        return redirect(url_for("pagina_despesas"))

    if classificacao not in ("Fixa", "Variavel"):
        flash("Escolha uma classificação válida.", "error")
        return redirect(url_for("pagina_despesas"))

    cursor = con.cursor()
    try:
        data = conferir_data(cursor, data_texto)
        cursor.execute("""
            INSERT INTO DESPESA
            (ID_USUARIO, DESCRICAO, VALOR, DATA_DESPESA, CLASSIFICACAO)
            VALUES (?, ?, ?, ?, ?)
        """, (session["id_usuario"], descricao, valor, data, classificacao))

        atualizar_saldo_mensal(cursor, session["id_usuario"], data)
        con.commit()
        flash("Despesa cadastrada com sucesso!", "success")
    except ValueError:
        con.rollback()
        flash("Informe uma data válida.", "error")
    except Exception:
        con.rollback()
        flash("Não foi possível cadastrar. Verifique a data e os campos.", "error")
    finally:
        cursor.close()
    return redirect(url_for("pagina_despesas"))


# Edita somente um movimento que pertence ao usuario logado.
@app.route("/despesas/editar/<int:id_registro>", methods=["POST"])
def editar_despesa(id_registro):
    if not usuario_autenticado():
        return redirect(url_for("login"))

    descricao = request.form.get("descricao", "").strip()
    valor = valor_positivo(request.form.get("valor", ""))
    data_texto = request.form.get("data", "")

    classificacao = request.form.get("classificacao", "")
    if not descricao or len(descricao) > 100 or valor is None:
        flash("Informe uma descrição e um valor positivo válido.", "error")
        return redirect(url_for("pagina_despesas"))

    if classificacao not in ("Fixa", "Variavel"):
        flash("Escolha uma classificação válida.", "error")
        return redirect(url_for("pagina_despesas"))

    cursor = con.cursor()
    try:
        cursor.execute("""
            SELECT DATA_DESPESA FROM DESPESA
            WHERE ID_DESPESA = ? AND ID_USUARIO = ?
        """, (id_registro, session["id_usuario"]))
        anterior = cursor.fetchone()
        if not anterior:
            flash("Despesa não encontrada.", "error")
            return redirect(url_for("pagina_despesas"))

        nova_data = conferir_data(cursor, data_texto)
        cursor.execute("""
            UPDATE DESPESA SET DESCRICAO = ?, VALOR = ?, DATA_DESPESA = ?, CLASSIFICACAO = ?
            WHERE ID_DESPESA = ? AND ID_USUARIO = ?
        """, (descricao, valor, nova_data, classificacao, id_registro, session["id_usuario"]))

        atualizar_saldo_mensal(cursor, session["id_usuario"], anterior[0])
        if anterior[0] != nova_data:
            atualizar_saldo_mensal(cursor, session["id_usuario"], nova_data)
        con.commit()
        flash("Despesa atualizada com sucesso!", "success")
    except ValueError:
        con.rollback()
        flash("Informe uma data válida.", "error")
    except Exception:
        con.rollback()
        flash("Não foi possível editar. Verifique os dados.", "error")
    finally:
        cursor.close()
    return redirect(url_for("pagina_despesas"))


# Exclui somente o movimento pertencente ao usuario logado.
@app.route("/despesas/excluir/<int:id_registro>", methods=["POST"])
def excluir_despesa(id_registro):
    if not usuario_autenticado():
        return redirect(url_for("login"))

    cursor = con.cursor()
    try:
        cursor.execute("""
            SELECT DATA_DESPESA FROM DESPESA
            WHERE ID_DESPESA = ? AND ID_USUARIO = ?
        """, (id_registro, session["id_usuario"]))
        anterior = cursor.fetchone()
        if not anterior:
            flash("Despesa não encontrada.", "error")
            return redirect(url_for("pagina_despesas"))

        cursor.execute("""
            DELETE FROM DESPESA WHERE ID_DESPESA = ? AND ID_USUARIO = ?
        """, (id_registro, session["id_usuario"]))
        atualizar_saldo_mensal(cursor, session["id_usuario"], anterior[0])
        con.commit()
        flash("Despesa excluída com sucesso!", "success")
    except Exception:
        con.rollback()
        flash("Não foi possível excluir a despesa.", "error")
    finally:
        cursor.close()
    return redirect(url_for("pagina_despesas"))


# Exibe os saldos mensais armazenados do usuario logado.
@app.route("/saldos_mensais")
def pagina_saldos_mensais():
    if not usuario_autenticado():
        return redirect(url_for("login"))

    cursor = con.cursor()
    try:
        cursor.execute("""
            SELECT ANO, MES, TOTAL_RECEITAS, TOTAL_DESPESAS, SALDO
            FROM SALDO_MENSAL WHERE ID_USUARIO = ?
            ORDER BY ANO DESC, MES DESC
        """, (session["id_usuario"],))
        saldos = cursor.fetchall()
        return render_template("saldos_mensais.html", saldos=saldos)
    except Exception:
        flash("Erro ao consultar os saldos.", "error")
        return redirect(url_for("novo"))
    finally:
        con.rollback()
        cursor.close()


# Taxas por data: esta tabela e separada de TAXA_EXERCICIO, que utiliza anos.
@app.route("/taxas")
def pagina_taxas():
    if not usuario_autenticado():
        return redirect(url_for("login"))

    cursor = con.cursor()
    try:
        id_edicao = request.args.get("editar", type=int)
        editar = None
        if id_edicao:
            cursor.execute("""
                SELECT ID_TAXA, PERCENTUAL, DATA_REFERENCIA
                FROM TAXA_JUROS WHERE ID_TAXA = ? AND ID_USUARIO = ?
            """, (id_edicao, session["id_usuario"]))
            editar = cursor.fetchone()
            if not editar:
                flash("Taxa não encontrada ou sem permissão.", "error")
                return redirect(url_for("pagina_taxas"))

        cursor.execute("""
            SELECT ID_TAXA, PERCENTUAL, DATA_REFERENCIA, ID_USUARIO
            FROM TAXA_JUROS ORDER BY DATA_REFERENCIA DESC
        """)
        taxas = cursor.fetchall()
        return render_template("taxas.html", taxas=taxas, editar=editar)
    except Exception:
        flash("Não foi possível consultar as taxas.", "error")
        return redirect(url_for("novo"))
    finally:
        con.rollback()
        cursor.close()


# A data da taxa e preenchida automaticamente pelo Firebird (CURRENT_DATE).
@app.route("/taxas/cadastrar", methods=["POST"])
def cadastrar_taxa():
    if not usuario_autenticado():
        return redirect(url_for("login"))

    try:
        percentual = float(request.form.get("percentual", ""))
        if not (0 <= percentual < 100000):
            raise ValueError("Taxa inválida")
    except ValueError:
        flash("Informe um percentual válido, sem valores negativos.", "error")
        return redirect(url_for("pagina_taxas"))

    cursor = con.cursor()
    try:
        cursor.execute("""
            SELECT ID_TAXA FROM TAXA_JUROS
            WHERE DATA_REFERENCIA = CURRENT_DATE
        """)
        if cursor.fetchone():
            flash("Já existe uma taxa cadastrada para a data de hoje.", "error")
            return redirect(url_for("pagina_taxas"))

        cursor.execute("""
            INSERT INTO TAXA_JUROS (ID_USUARIO, PERCENTUAL, DATA_REFERENCIA)
            VALUES (?, ?, CURRENT_DATE)
        """, (session["id_usuario"], percentual))
        con.commit()
        flash("Taxa cadastrada com sucesso!", "success")
    except Exception:
        con.rollback()
        flash("Não foi possível cadastrar. Verifique se já existe taxa hoje.", "error")
    finally:
        cursor.close()
    return redirect(url_for("pagina_taxas"))


# Edita somente o percentual; a data original nao pode ser alterada manualmente.
@app.route("/taxas/editar/<int:id_taxa>", methods=["POST"])
def editar_taxa(id_taxa):
    if not usuario_autenticado():
        return redirect(url_for("login"))

    try:
        percentual = float(request.form.get("percentual", ""))
        if not (0 <= percentual < 100000):
            raise ValueError("Taxa inválida")
    except ValueError:
        flash("Informe um percentual válido.", "error")
        return redirect(url_for("pagina_taxas"))

    cursor = con.cursor()
    try:
        cursor.execute("""
            UPDATE TAXA_JUROS SET PERCENTUAL = ?
            WHERE ID_TAXA = ? AND ID_USUARIO = ?
        """, (percentual, id_taxa, session["id_usuario"]))
        if cursor.rowcount == 0:
            flash("Taxa não encontrada ou sem permissão.", "error")
            return redirect(url_for("pagina_taxas"))
        con.commit()
        flash("Taxa atualizada com sucesso!", "success")
    except Exception:
        con.rollback()
        flash("Erro ao atualizar taxa.", "error")
    finally:
        cursor.close()
    return redirect(url_for("pagina_taxas"))


@app.route("/taxas/excluir/<int:id_taxa>", methods=["POST"])
def excluir_taxa(id_taxa):
    if not usuario_autenticado():
        return redirect(url_for("login"))

    cursor = con.cursor()
    try:
        cursor.execute("""
            DELETE FROM TAXA_JUROS
            WHERE ID_TAXA = ? AND ID_USUARIO = ?
        """, (id_taxa, session["id_usuario"]))
        if cursor.rowcount == 0:
            flash("Taxa não encontrada ou sem permissão.", "error")
            return redirect(url_for("pagina_taxas"))
        con.commit()
        flash("Taxa excluída com sucesso!", "success")
    except Exception:
        con.rollback()
        flash("Erro ao excluir taxa.", "error")
    finally:
        cursor.close()
    return redirect(url_for("pagina_taxas"))

# INICIA O SERVIDOR

if __name__ == "__main__":
    # Atende uma requisição por vez porque o projeto usa uma conexão global.
    app.run(debug=True, threaded=False)
