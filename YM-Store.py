import os
import secrets
from datetime import datetime, date
from decimal import Decimal
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, redirect, url_for, flash, session,
    send_from_directory, abort, render_template_string
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ============================================================
# YM STORE - SISTEMA WEB
# Flask + SQLite / PostgreSQL
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "ym-store-cambia-esta-clave-en-produccion")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "sqlite:///" + str(BASE_DIR / "ym_store.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)

db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "pdf"}


# ============================================================
# HELPERS
# ============================================================

def money(value):
    value = Decimal(value or 0)
    return f"${value:,.2f}"

app.jinja_env.filters["money"] = money


def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Inicia sesión para continuar.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if user.role != "ADMIN":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_upload(file_storage):
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename):
        raise ValueError("Formato no permitido. Usa JPG, PNG, WEBP o PDF.")
    original = secure_filename(file_storage.filename)
    ext = original.rsplit(".", 1)[1].lower()
    filename = f"{datetime.now():%Y%m%d%H%M%S}_{secrets.token_hex(8)}.{ext}"
    file_storage.save(UPLOAD_DIR / filename)
    return filename


def client_balance(client_id):
    charges = db.session.query(func.coalesce(func.sum(AccountMovement.charge), 0)).filter(
        AccountMovement.client_id == client_id
    ).scalar()
    credits = db.session.query(func.coalesce(func.sum(AccountMovement.credit), 0)).filter(
        AccountMovement.client_id == client_id
    ).scalar()
    return Decimal(charges or 0) - Decimal(credits or 0)


def create_account_movement(client_id, movement_type, concept, charge=0, credit=0, reference=None):
    movement = AccountMovement(
        client_id=client_id,
        movement_type=movement_type,
        concept=concept,
        charge=Decimal(str(charge or 0)),
        credit=Decimal(str(credit or 0)),
        reference=reference,
        created_at=datetime.now()
    )
    db.session.add(movement)
    return movement


def add_inventory_movement(product, movement_type, quantity, reference=None, notes=None):
    movement = InventoryMovement(
        product_id=product.id,
        movement_type=movement_type,
        quantity=int(quantity),
        reference=reference,
        notes=notes,
        created_at=datetime.now()
    )
    db.session.add(movement)
    return movement


# ============================================================
# MODELS
# ============================================================

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="ADMIN")
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Client(db.Model):
    __tablename__ = "clients"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, index=True)
    phone = db.Column(db.String(30))
    email = db.Column(db.String(150))
    address = db.Column(db.String(300))
    notes = db.Column(db.Text)
    active = db.Column(db.Boolean, nullable=False, default=True)
    payment_token = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        default=lambda: secrets.token_urlsafe(24)
    )
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    sales = db.relationship("Sale", backref="client", lazy=True)
    movements = db.relationship("AccountMovement", backref="client", lazy=True, cascade="all, delete-orphan")
    payments = db.relationship("Payment", backref="client", lazy=True, cascade="all, delete-orphan")


class Product(db.Model):
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(60), unique=True, nullable=False, index=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    purchase_price = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    sale_price = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    stock = db.Column(db.Integer, nullable=False, default=0)
    minimum_stock = db.Column(db.Integer, nullable=False, default=0)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)


class InventoryMovement(db.Model):
    __tablename__ = "inventory_movements"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    movement_type = db.Column(db.String(30), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    reference = db.Column(db.String(100))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    product = db.relationship("Product", backref="inventory_movements")


class Purchase(db.Model):
    __tablename__ = "purchases"

    id = db.Column(db.Integer, primary_key=True)
    supplier = db.Column(db.String(150), nullable=False)
    total = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    items = db.relationship("PurchaseItem", backref="purchase", cascade="all, delete-orphan")


class PurchaseItem(db.Model):
    __tablename__ = "purchase_items"

    id = db.Column(db.Integer, primary_key=True)
    purchase_id = db.Column(db.Integer, db.ForeignKey("purchases.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_cost = db.Column(db.Numeric(12, 2), nullable=False)
    subtotal = db.Column(db.Numeric(12, 2), nullable=False)

    product = db.relationship("Product")


class Sale(db.Model):
    __tablename__ = "sales"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    total = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    paid_now = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    status = db.Column(db.String(30), nullable=False, default="PENDIENTE")
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    items = db.relationship("SaleItem", backref="sale", cascade="all, delete-orphan")


class SaleItem(db.Model):
    __tablename__ = "sale_items"

    id = db.Column(db.Integer, primary_key=True)
    sale_id = db.Column(db.Integer, db.ForeignKey("sales.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Numeric(12, 2), nullable=False)
    subtotal = db.Column(db.Numeric(12, 2), nullable=False)

    product = db.relationship("Product")


class AccountMovement(db.Model):
    __tablename__ = "account_movements"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    movement_type = db.Column(db.String(30), nullable=False)
    concept = db.Column(db.String(255), nullable=False)
    charge = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    credit = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    reference = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)


class Payment(db.Model):
    __tablename__ = "payments"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    reference = db.Column(db.String(150))
    receipt_file = db.Column(db.String(255))
    status = db.Column(db.String(30), nullable=False, default="PENDIENTE")
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    approved_at = db.Column(db.DateTime)


class Tanda(db.Model):
    __tablename__ = "tandas"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    payment_amount = db.Column(db.Numeric(12, 2), nullable=False)
    frequency = db.Column(db.String(30), nullable=False, default="SEMANAL")
    start_date = db.Column(db.Date, nullable=False, default=date.today)
    status = db.Column(db.String(30), nullable=False, default="ACTIVA")
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    participants = db.relationship("TandaParticipant", backref="tanda", cascade="all, delete-orphan")


class TandaParticipant(db.Model):
    __tablename__ = "tanda_participants"

    id = db.Column(db.Integer, primary_key=True)
    tanda_id = db.Column(db.Integer, db.ForeignKey("tandas.id"), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    turn_number = db.Column(db.Integer, nullable=False)
    total_due = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    paid = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    status = db.Column(db.String(30), nullable=False, default="PENDIENTE")

    client = db.relationship("Client")
    payments = db.relationship("TandaPayment", backref="participant", cascade="all, delete-orphan")


class TandaPayment(db.Model):
    __tablename__ = "tanda_payments"

    id = db.Column(db.Integer, primary_key=True)
    participant_id = db.Column(db.Integer, db.ForeignKey("tanda_participants.id"), nullable=False)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    receipt_file = db.Column(db.String(255))
    notes = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)


# ============================================================
# UI
# ============================================================

BASE_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title or 'YM Store' }}</title>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

  <style>
    :root{
      --navy:#070d24;
      --navy-2:#0d1534;
      --surface:#ffffff;
      --bg:#f5f7fb;
      --text:#111827;
      --muted:#7a8499;
      --purple:#7047ff;
      --pink:#ef4ba1;
      --blue:#1795f5;
      --green:#15bb75;
      --orange:#ff9d12;
      --cyan:#0bcfc7;
      --danger:#ff4d62;
      --shadow:0 14px 40px rgba(30,41,59,.08);
      --radius:22px;
    }

    *{box-sizing:border-box}
    body{
      margin:0;
      font-family:'Inter',system-ui,-apple-system,sans-serif;
      background:var(--bg);
      color:var(--text);
    }

    a{text-decoration:none}
    .app-shell{min-height:100vh}

    .sidebar{
      position:fixed;
      top:0;left:0;bottom:0;
      width:245px;
      padding:22px 16px;
      background:
        radial-gradient(circle at 20% 10%, rgba(112,71,255,.20), transparent 28%),
        linear-gradient(180deg,var(--navy),#061027 100%);
      color:#dbe3ff;
      overflow-y:auto;
      z-index:1000;
      border-right:1px solid rgba(255,255,255,.05);
    }

    .brand{
      display:flex;
      align-items:center;
      gap:12px;
      padding:4px 8px 22px;
    }

    .brand-mark{
      width:52px;height:52px;
      border-radius:16px;
      display:grid;place-items:center;
      font-weight:900;
      font-size:21px;
      letter-spacing:-2px;
      color:#fff;
      background:
        linear-gradient(135deg,#ff9a1a 0%,#ff3f87 27%,#7446ff 58%,#169cff 100%);
      box-shadow:0 10px 30px rgba(112,71,255,.35);
      position:relative;
      overflow:hidden;
    }

    .brand-mark::after{
      content:"";
      position:absolute;
      width:28px;height:28px;
      border:4px solid rgba(255,255,255,.22);
      border-radius:50%;
      right:-8px;top:-8px;
    }

    .brand-title{font-weight:900;font-size:20px;letter-spacing:.4px;color:#fff}
    .brand-sub{font-size:11px;color:#8e9ab9;margin-top:2px}

    .nav-section{
      font-size:10px;
      text-transform:uppercase;
      letter-spacing:1.3px;
      color:#74809e;
      margin:20px 12px 8px;
    }

    .side-link{
      color:#dbe3ff;
      padding:11px 12px;
      display:flex;
      align-items:center;
      gap:11px;
      border-radius:13px;
      margin-bottom:4px;
      font-size:13px;
      font-weight:600;
      transition:.2s ease;
    }

    .side-link i{font-size:17px;width:22px;text-align:center}
    .side-link:hover{
      color:#fff;
      background:rgba(255,255,255,.08);
      transform:translateX(2px);
    }
    .side-link.active{
      color:#fff;
      background:linear-gradient(135deg,#5c3bff,#7d4cff);
      box-shadow:0 10px 24px rgba(99,65,255,.35);
    }

    .side-user{
      margin-top:20px;
      padding:14px;
      border-radius:18px;
      background:rgba(255,255,255,.05);
      border:1px solid rgba(255,255,255,.06);
    }

    .avatar{
      width:42px;height:42px;
      display:grid;place-items:center;
      border-radius:50%;
      background:linear-gradient(135deg,#ff9b1a,#ef4ba1,#7047ff);
      color:white;font-weight:900;
    }

    .main{
      margin-left:245px;
      min-height:100vh;
    }

    .topbar{
      height:76px;
      background:rgba(255,255,255,.92);
      backdrop-filter:blur(10px);
      border-bottom:1px solid #e9edf5;
      display:flex;
      align-items:center;
      justify-content:space-between;
      padding:0 28px;
      position:sticky;
      top:0;
      z-index:900;
    }

    .searchbox{
      width:min(440px,45vw);
      position:relative;
    }
    .searchbox input{
      width:100%;
      border:1px solid #e4e9f2;
      background:#fff;
      border-radius:14px;
      padding:12px 44px 12px 16px;
      outline:none;
      font-size:13px;
      box-shadow:0 5px 20px rgba(15,23,42,.03);
    }
    .searchbox i{
      position:absolute;
      right:16px;top:50%;
      transform:translateY(-50%);
      color:#657189;
    }

    .content{padding:28px}

    .hero-title{
      font-size:25px;
      font-weight:900;
      letter-spacing:-.5px;
      margin-bottom:4px;
    }
    .hero-sub{color:var(--muted);font-size:13px}

    .panel{
      background:#fff;
      border:1px solid #edf0f6;
      border-radius:var(--radius);
      box-shadow:var(--shadow);
    }

    .stat-card{
      border-radius:20px;
      padding:20px;
      color:#fff;
      min-height:132px;
      position:relative;
      overflow:hidden;
      box-shadow:0 14px 30px rgba(25,32,56,.10);
    }
    .stat-card::after{
      content:"";
      position:absolute;
      width:115px;height:115px;
      border-radius:50%;
      background:rgba(255,255,255,.10);
      right:-25px;top:-25px;
    }
    .stat-purple{background:linear-gradient(135deg,#5f3cff,#8749ff)}
    .stat-green{background:linear-gradient(135deg,#11b667,#26d28c)}
    .stat-orange{background:linear-gradient(135deg,#ff9a0f,#ffb416)}
    .stat-blue{background:linear-gradient(135deg,#098be9,#116de7)}
    .stat-pink{background:linear-gradient(135deg,#e9439e,#f05eb4)}

    .stat-label{font-size:12px;font-weight:600;opacity:.95}
    .stat-value{font-size:25px;font-weight:900;margin-top:10px;letter-spacing:-.7px}
    .stat-foot{font-size:11px;margin-top:10px;opacity:.92}
    .stat-icon{
      position:absolute;right:18px;bottom:18px;
      width:50px;height:50px;border-radius:50%;
      background:rgba(255,255,255,.9);
      display:grid;place-items:center;
      color:#29314c;font-size:23px;
      z-index:2;
    }

    .section-title{font-size:15px;font-weight:800;margin:0}
    .section-sub{font-size:12px;color:var(--muted)}

    .quick{
      min-height:110px;
      border-radius:18px;
      padding:16px;
      color:#fff;
      display:flex;flex-direction:column;
      justify-content:space-between;
      font-weight:700;
      transition:.2s ease;
    }
    .quick:hover{transform:translateY(-3px);color:#fff}
    .quick i{font-size:26px}

    .table{
      --bs-table-bg:transparent;
      margin-bottom:0;
    }
    .table thead th{
      color:#77819a;
      font-size:11px;
      text-transform:uppercase;
      letter-spacing:.6px;
      border-bottom:1px solid #edf0f6;
      padding:13px 12px;
      white-space:nowrap;
    }
    .table tbody td{
      padding:14px 12px;
      border-color:#f0f2f7;
      vertical-align:middle;
      font-size:13px;
    }

    .form-control,.form-select{
      border-radius:13px;
      padding:11px 13px;
      border:1px solid #dfe5ef;
      font-size:13px;
    }
    .form-control:focus,.form-select:focus{
      border-color:#8a69ff;
      box-shadow:0 0 0 .22rem rgba(112,71,255,.12);
    }

    .btn{
      border-radius:12px;
      font-weight:700;
      font-size:13px;
      padding:10px 15px;
    }
    .btn-gradient{
      color:#fff;
      border:0;
      background:linear-gradient(135deg,#5f3cff,#8a4fff);
      box-shadow:0 8px 20px rgba(112,71,255,.24);
    }
    .btn-gradient:hover{color:#fff;filter:brightness(1.03)}
    .badge-soft{
      background:#f1efff;
      color:#6c44f5;
      border-radius:999px;
      padding:7px 10px;
      font-weight:700;
    }

    .debt{color:#e23b52;font-weight:800}
    .credit{color:#0da466;font-weight:800}

    .login-page{
      min-height:100vh;
      background:
        radial-gradient(circle at 15% 20%, rgba(239,75,161,.18), transparent 25%),
        radial-gradient(circle at 80% 18%, rgba(23,149,245,.18), transparent 25%),
        radial-gradient(circle at 70% 80%, rgba(112,71,255,.18), transparent 25%),
        linear-gradient(135deg,#f8f8ff,#f2f5fb);
      display:grid;
      place-items:center;
      padding:20px;
    }
    .login-card{
      width:min(950px,96vw);
      overflow:hidden;
      border-radius:28px;
      background:#fff;
      box-shadow:0 30px 80px rgba(30,41,59,.16);
      display:grid;
      grid-template-columns:1.05fr .95fr;
    }
    .login-brand{
      min-height:570px;
      padding:54px;
      color:#fff;
      background:
        radial-gradient(circle at 80% 15%, rgba(255,255,255,.16), transparent 22%),
        linear-gradient(145deg,#081127,#121a3d 52%,#2b1a70);
      display:flex;
      flex-direction:column;
      justify-content:space-between;
    }
    .login-form{padding:56px}
    .login-logo{
      width:92px;height:92px;border-radius:27px;
      display:grid;place-items:center;
      font-size:35px;font-weight:900;letter-spacing:-4px;
      background:linear-gradient(135deg,#ff9a1a,#ff3f87,#7446ff,#169cff);
      box-shadow:0 20px 45px rgba(112,71,255,.35);
    }

    .progress-thin{height:7px;border-radius:999px;background:#eef1f7;overflow:hidden}
    .progress-thin span{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,#5f3cff,#169cff)}

    @media (max-width: 991px){
      .sidebar{transform:translateX(-100%);transition:.25s}
      .sidebar.show{transform:translateX(0)}
      .main{margin-left:0}
      .topbar{padding:0 15px}
      .content{padding:18px 14px}
      .searchbox{width:65vw}
      .login-card{grid-template-columns:1fr}
      .login-brand{display:none}
      .login-form{padding:36px 26px}
    }

    .alert{border-radius:16px;border:0;box-shadow:0 10px 30px rgba(30,41,59,.07)}
  </style>
</head>
<body>

{% if user %}
<div class="app-shell">
  <aside class="sidebar" id="sidebar">
    <div class="brand">
      <div class="brand-mark">YM</div>
      <div>
        <div class="brand-title">YM Store</div>
        <div class="brand-sub">Todo en un solo lugar</div>
      </div>
    </div>

    <a class="side-link {{ 'active' if active=='dashboard' else '' }}" href="{{ url_for('dashboard') }}">
      <i class="bi bi-grid-1x2-fill"></i> Dashboard
    </a>

    <div class="nav-section">Módulos</div>
    <a class="side-link {{ 'active' if active=='clients' else '' }}" href="{{ url_for('clients') }}">
      <i class="bi bi-people"></i> Clientes
    </a>
    <a class="side-link {{ 'active' if active=='payments' else '' }}" href="{{ url_for('payments_admin') }}">
      <i class="bi bi-wallet2"></i> Deudas y pagos
    </a>
    <a class="side-link {{ 'active' if active=='products' else '' }}" href="{{ url_for('products') }}">
      <i class="bi bi-box-seam"></i> Inventario
    </a>
    <a class="side-link {{ 'active' if active=='purchases' else '' }}" href="{{ url_for('purchases') }}">
      <i class="bi bi-cart-plus"></i> Compras
    </a>
    <a class="side-link {{ 'active' if active=='sales' else '' }}" href="{{ url_for('sales') }}">
      <i class="bi bi-bag-check"></i> Ventas
    </a>
    <a class="side-link {{ 'active' if active=='tandas' else '' }}" href="{{ url_for('tandas') }}">
      <i class="bi bi-coin"></i> Tandas
    </a>

    <div class="nav-section">Administración</div>
    <a class="side-link" href="{{ url_for('logout') }}">
      <i class="bi bi-box-arrow-left"></i> Cerrar sesión
    </a>

    <div class="side-user">
      <div class="d-flex align-items-center gap-3">
        <div class="avatar">{{ user.name[:1].upper() }}</div>
        <div>
          <div style="font-size:12px;font-weight:800;color:white">{{ user.name }}</div>
          <div style="font-size:10px;color:#8e9ab9">{{ user.role }}</div>
        </div>
      </div>
    </div>
  </aside>

  <div class="main">
    <header class="topbar">
      <div class="d-flex align-items-center gap-3">
        <button class="btn btn-gradient d-lg-none" onclick="document.getElementById('sidebar').classList.toggle('show')">
          <i class="bi bi-list"></i>
        </button>
        <div class="searchbox d-none d-md-block">
          <input placeholder="Buscar en YM Store..." disabled>
          <i class="bi bi-search"></i>
        </div>
      </div>
      <div class="d-flex align-items-center gap-3">
        <span class="badge-soft"><i class="bi bi-shield-check me-1"></i> Seguro</span>
        <div class="avatar" style="width:38px;height:38px">{{ user.name[:1].upper() }}</div>
      </div>
    </header>

    <main class="content">
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, message in messages %}
          <div class="alert alert-{{ 'danger' if category in ['error','danger'] else category }} alert-dismissible fade show">
            {{ message }}
            <button class="btn-close" data-bs-dismiss="alert"></button>
          </div>
        {% endfor %}
      {% endwith %}
      {{ content|safe }}
    </main>
  </div>
</div>

{% else %}
  {{ content|safe }}
{% endif %}

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""


def page(content, title="YM Store", active="", **context):
    inner = render_template_string(content, **context)
    return render_template_string(
        BASE_TEMPLATE,
        content=inner,
        user=current_user(),
        title=title,
        active=active
    )


# ============================================================
# AUTH
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username, active=True).first()

        if user and user.check_password(password):
            session.clear()
            session["user_id"] = user.id
            flash(f"Bienvenida, {user.name}.", "success")
            return redirect(url_for("dashboard"))

        flash("Usuario o contraseña incorrectos.", "danger")

    return page("""
    <div class="login-page">
      <div class="login-card">
        <section class="login-brand">
          <div>
            <div class="login-logo">YM</div>
            <h1 class="mt-4 fw-black" style="font-weight:900;font-size:42px">YM Store</h1>
            <p style="color:#b8c2df;font-size:15px">Compras, pagos, inventario y tandas en una sola plataforma.</p>
          </div>

          <div>
            <div class="d-flex gap-3 flex-wrap mb-4">
              <span class="badge rounded-pill text-bg-light px-3 py-2"><i class="bi bi-bag-check me-1"></i> Ventas</span>
              <span class="badge rounded-pill text-bg-light px-3 py-2"><i class="bi bi-wallet2 me-1"></i> Pagos</span>
              <span class="badge rounded-pill text-bg-light px-3 py-2"><i class="bi bi-box-seam me-1"></i> Inventario</span>
            </div>
            <div style="font-size:12px;color:#8190b8">Administración profesional para YM Store.</div>
          </div>
        </section>

        <section class="login-form">
          <div class="mb-5">
            <div class="badge-soft d-inline-block mb-3">Panel administrativo</div>
            <h2 class="fw-bold mb-2" style="font-size:30px">Bienvenida 👋</h2>
            <p class="text-secondary">Ingresa para administrar tu negocio.</p>
          </div>

          {% with messages = get_flashed_messages(with_categories=true) %}
            {% for category, message in messages %}
              <div class="alert alert-{{ 'danger' if category=='danger' else category }}">{{ message }}</div>
            {% endfor %}
          {% endwith %}

          <form method="post">
            <label class="form-label fw-bold">Usuario</label>
            <div class="input-group mb-3">
              <span class="input-group-text bg-white border-end-0"><i class="bi bi-person"></i></span>
              <input class="form-control border-start-0" name="username" required autofocus placeholder="admin">
            </div>

            <label class="form-label fw-bold">Contraseña</label>
            <div class="input-group mb-4">
              <span class="input-group-text bg-white border-end-0"><i class="bi bi-lock"></i></span>
              <input class="form-control border-start-0" type="password" name="password" required placeholder="••••••••">
            </div>

            <button class="btn btn-gradient w-100 py-3">
              Entrar a YM Store <i class="bi bi-arrow-right ms-2"></i>
            </button>
          </form>

          <div class="text-center text-secondary mt-4" style="font-size:11px">
            YM Store • Todo en un solo lugar
          </div>
        </section>
      </div>
    </div>
    """, title="Iniciar sesión")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
@login_required
def dashboard():
    total_clients = Client.query.filter_by(active=True).count()
    total_products = Product.query.filter_by(active=True).count()
    low_stock_products = Product.query.filter(
        Product.active.is_(True),
        Product.stock <= Product.minimum_stock
    ).order_by(Product.stock.asc()).limit(6).all()

    total_debt = sum((client_balance(c.id) for c in Client.query.filter_by(active=True).all()), Decimal("0"))
    pending_payments = Payment.query.filter_by(status="PENDIENTE").count()
    sales_total = Decimal(db.session.query(func.coalesce(func.sum(Sale.total), 0)).scalar() or 0)
    active_tandas = Tanda.query.filter_by(status="ACTIVA").count()

    recent_sales = Sale.query.order_by(Sale.created_at.desc()).limit(5).all()
    recent_payments = Payment.query.order_by(Payment.created_at.desc()).limit(5).all()

    debtors = []
    for client in Client.query.filter_by(active=True).all():
        bal = client_balance(client.id)
        if bal > 0:
            debtors.append((client, bal))
    debtors = sorted(debtors, key=lambda x: x[1], reverse=True)[:5]

    return page("""
    <div class="mb-4">
      <div class="hero-title">¡Bienvenido de vuelta, {{ current.name }}! 👋</div>
      <div class="hero-sub">Aquí tienes un resumen general de YM Store.</div>
    </div>

    <div class="row g-3 mb-4">
      <div class="col-12 col-md-6 col-xl">
        <div class="stat-card stat-purple">
          <div class="stat-label">Ventas acumuladas</div>
          <div class="stat-value">{{ sales_total|money }}</div>
          <div class="stat-foot">Histórico registrado</div>
          <div class="stat-icon"><i class="bi bi-bag-fill"></i></div>
        </div>
      </div>
      <div class="col-12 col-md-6 col-xl">
        <div class="stat-card stat-green">
          <div class="stat-label">Clientes activos</div>
          <div class="stat-value">{{ total_clients }}</div>
          <div class="stat-foot">Clientes registrados</div>
          <div class="stat-icon"><i class="bi bi-people-fill"></i></div>
        </div>
      </div>
      <div class="col-12 col-md-6 col-xl">
        <div class="stat-card stat-orange">
          <div class="stat-label">Deuda total</div>
          <div class="stat-value">{{ total_debt|money }}</div>
          <div class="stat-foot">{{ pending_payments }} comprobantes pendientes</div>
          <div class="stat-icon"><i class="bi bi-wallet2"></i></div>
        </div>
      </div>
      <div class="col-12 col-md-6 col-xl">
        <div class="stat-card stat-blue">
          <div class="stat-label">Productos</div>
          <div class="stat-value">{{ total_products }}</div>
          <div class="stat-foot">{{ low_stock_products|length }} con stock bajo</div>
          <div class="stat-icon"><i class="bi bi-box-seam-fill"></i></div>
        </div>
      </div>
      <div class="col-12 col-md-6 col-xl">
        <div class="stat-card stat-pink">
          <div class="stat-label">Tandas activas</div>
          <div class="stat-value">{{ active_tandas }}</div>
          <div class="stat-foot">En progreso</div>
          <div class="stat-icon"><i class="bi bi-coin"></i></div>
        </div>
      </div>
    </div>

    <div class="panel p-4 mb-4">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
          <h2 class="section-title">Accesos rápidos</h2>
          <div class="section-sub">Las acciones que más usas</div>
        </div>
      </div>

      <div class="row g-3">
        <div class="col-6 col-md-4 col-xl-2">
          <a href="{{ url_for('sales') }}" class="quick" style="background:linear-gradient(135deg,#15bb75,#25d58f)">
            <i class="bi bi-cart-check"></i><span>Nueva venta</span>
          </a>
        </div>
        <div class="col-6 col-md-4 col-xl-2">
          <a href="{{ url_for('clients') }}" class="quick" style="background:linear-gradient(135deg,#248ef1,#3d79ff)">
            <i class="bi bi-person-plus"></i><span>Agregar cliente</span>
          </a>
        </div>
        <div class="col-6 col-md-4 col-xl-2">
          <a href="{{ url_for('payments_admin') }}" class="quick" style="background:linear-gradient(135deg,#ff9d12,#ffc21e)">
            <i class="bi bi-cash-coin"></i><span>Registrar pago</span>
          </a>
        </div>
        <div class="col-6 col-md-4 col-xl-2">
          <a href="{{ url_for('purchases') }}" class="quick" style="background:linear-gradient(135deg,#ef4ba1,#ff6fb8)">
            <i class="bi bi-cart-plus"></i><span>Nueva compra</span>
          </a>
        </div>
        <div class="col-6 col-md-4 col-xl-2">
          <a href="{{ url_for('products') }}" class="quick" style="background:linear-gradient(135deg,#7047ff,#8c5dff)">
            <i class="bi bi-box-seam"></i><span>Agregar producto</span>
          </a>
        </div>
        <div class="col-6 col-md-4 col-xl-2">
          <a href="{{ url_for('tandas') }}" class="quick" style="background:linear-gradient(135deg,#0bcfc7,#10b8dc)">
            <i class="bi bi-people"></i><span>Nueva tanda</span>
          </a>
        </div>
      </div>
    </div>

    <div class="row g-4">
      <div class="col-xl-4">
        <div class="panel p-4 h-100">
          <h2 class="section-title mb-3">Deudas principales</h2>
          {% for c, bal in debtors %}
            <div class="d-flex align-items-center justify-content-between py-3 border-bottom">
              <div class="d-flex align-items-center gap-3">
                <div class="avatar">{{ c.name[:1].upper() }}</div>
                <div>
                  <div class="fw-bold" style="font-size:13px">{{ c.name }}</div>
                  <div class="section-sub">{{ c.phone or 'Sin teléfono' }}</div>
                </div>
              </div>
              <div class="debt">{{ bal|money }}</div>
            </div>
          {% else %}
            <div class="text-secondary py-4 text-center">No hay deudas pendientes.</div>
          {% endfor %}
          <a class="btn btn-light w-100 mt-3" href="{{ url_for('clients') }}">Ver todos los clientes</a>
        </div>
      </div>

      <div class="col-xl-4">
        <div class="panel p-4 h-100">
          <h2 class="section-title mb-3">Productos con bajo stock</h2>
          {% for p in low_stock_products %}
            <div class="py-3 border-bottom">
              <div class="d-flex justify-content-between align-items-center mb-2">
                <strong style="font-size:13px">{{ p.name }}</strong>
                <span class="badge text-bg-danger">¡Bajo!</span>
              </div>
              <div class="section-sub mb-2">Stock actual: {{ p.stock }} • Mínimo: {{ p.minimum_stock }}</div>
              <div class="progress-thin">
                <span style="width:{{ [100, ((p.stock / (p.minimum_stock if p.minimum_stock else 1))*100)]|min }}%"></span>
              </div>
            </div>
          {% else %}
            <div class="text-secondary py-4 text-center">Inventario saludable.</div>
          {% endfor %}
          <a class="btn btn-light w-100 mt-3" href="{{ url_for('products') }}">Ver inventario completo</a>
        </div>
      </div>

      <div class="col-xl-4">
        <div class="panel p-4 h-100">
          <h2 class="section-title mb-3">Actividad reciente</h2>
          {% for s in recent_sales %}
            <div class="d-flex gap-3 py-3 border-bottom">
              <div class="avatar" style="background:linear-gradient(135deg,#7047ff,#1795f5)"><i class="bi bi-bag-check"></i></div>
              <div>
                <div class="fw-bold" style="font-size:13px">Venta #{{ s.id }}</div>
                <div class="section-sub">{{ s.client.name }} • {{ s.total|money }}</div>
              </div>
            </div>
          {% endfor %}
          {% for p in recent_payments %}
            <div class="d-flex gap-3 py-3 border-bottom">
              <div class="avatar" style="background:linear-gradient(135deg,#15bb75,#0bcfc7)"><i class="bi bi-cash"></i></div>
              <div>
                <div class="fw-bold" style="font-size:13px">Pago {{ p.status.lower() }}</div>
                <div class="section-sub">{{ p.client.name }} • {{ p.amount|money }}</div>
              </div>
            </div>
          {% endfor %}
        </div>
      </div>
    </div>
    """,
    title="Dashboard",
    active="dashboard",
    current=current_user(),
    sales_total=sales_total,
    total_clients=total_clients,
    total_debt=total_debt,
    pending_payments=pending_payments,
    total_products=total_products,
    active_tandas=active_tandas,
    low_stock_products=low_stock_products,
    recent_sales=recent_sales,
    recent_payments=recent_payments,
    debtors=debtors
    )


# ============================================================
# CLIENTES / DEUDAS / PAGOS
# ============================================================

@app.route("/clientes", methods=["GET", "POST"])
@login_required
def clients():
    if request.method == "POST":
        try:
            name = request.form.get("name", "").strip()
            if not name:
                raise ValueError("El nombre es obligatorio.")

            client = Client(
                name=name,
                phone=request.form.get("phone", "").strip(),
                email=request.form.get("email", "").strip(),
                address=request.form.get("address", "").strip(),
                notes=request.form.get("notes", "").strip()
            )
            db.session.add(client)
            db.session.commit()
            flash("Cliente creado correctamente.", "success")
            return redirect(url_for("client_detail", client_id=client.id))
        except Exception as e:
            db.session.rollback()
            flash(str(e), "danger")

    q = request.args.get("q", "").strip()
    query = Client.query.filter_by(active=True)
    if q:
        query = query.filter(Client.name.ilike(f"%{q}%"))
    rows = query.order_by(Client.name).all()
    balances = {c.id: client_balance(c.id) for c in rows}

    return page("""
    <div class="d-flex justify-content-between align-items-start mb-4">
      <div>
        <div class="hero-title">Clientes</div>
        <div class="hero-sub">Administra tus clientes, saldos y datos de contacto.</div>
      </div>
    </div>

    <div class="row g-4">
      <div class="col-lg-4">
        <div class="panel p-4">
          <div class="d-flex align-items-center gap-3 mb-4">
            <div class="avatar" style="background:linear-gradient(135deg,#248ef1,#7047ff)"><i class="bi bi-person-plus"></i></div>
            <div><h2 class="section-title">Nuevo cliente</h2><div class="section-sub">Agrega sus datos principales</div></div>
          </div>
          <form method="post">
            <label class="form-label fw-bold">Nombre</label>
            <input class="form-control mb-3" name="name" required>
            <label class="form-label fw-bold">Teléfono</label>
            <input class="form-control mb-3" name="phone">
            <label class="form-label fw-bold">Correo</label>
            <input class="form-control mb-3" name="email">
            <label class="form-label fw-bold">Dirección</label>
            <input class="form-control mb-3" name="address">
            <label class="form-label fw-bold">Notas</label>
            <textarea class="form-control mb-4" name="notes" rows="3"></textarea>
            <button class="btn btn-gradient w-100"><i class="bi bi-check2-circle me-1"></i> Guardar cliente</button>
          </form>
        </div>
      </div>

      <div class="col-lg-8">
        <div class="panel p-4">
          <div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
            <div><h2 class="section-title">Directorio de clientes</h2><div class="section-sub">{{ rows|length }} clientes encontrados</div></div>
            <form method="get" class="d-flex gap-2">
              <input class="form-control" name="q" value="{{ request.args.get('q','') }}" placeholder="Buscar cliente">
              <button class="btn btn-light"><i class="bi bi-search"></i></button>
            </form>
          </div>

          <div class="table-responsive">
            <table class="table">
              <thead><tr><th>Cliente</th><th>Teléfono</th><th>Correo</th><th>Saldo</th><th></th></tr></thead>
              <tbody>
              {% for c in rows %}
                <tr>
                  <td>
                    <div class="d-flex align-items-center gap-2">
                      <div class="avatar" style="width:34px;height:34px">{{ c.name[:1].upper() }}</div>
                      <strong>{{ c.name }}</strong>
                    </div>
                  </td>
                  <td>{{ c.phone or '-' }}</td>
                  <td>{{ c.email or '-' }}</td>
                  <td class="{{ 'debt' if balances[c.id] > 0 else 'credit' }}">{{ balances[c.id]|money }}</td>
                  <td><a class="btn btn-sm btn-gradient" href="{{ url_for('client_detail', client_id=c.id) }}">Abrir</a></td>
                </tr>
              {% else %}
                <tr><td colspan="5" class="text-center text-secondary py-5">Sin clientes registrados.</td></tr>
              {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """, title="Clientes", active="clients", rows=rows, balances=balances, request=request)


@app.route("/clientes/<int:client_id>", methods=["GET", "POST"])
@login_required
def client_detail(client_id):
    client = db.session.get(Client, client_id)
    if not client:
        abort(404)

    if request.method == "POST":
        action = request.form.get("action")
        try:
            amount = Decimal(request.form.get("amount", "0"))
            if amount <= 0:
                raise ValueError("El monto debe ser mayor a cero.")

            if action == "charge":
                create_account_movement(
                    client.id,
                    "CARGO",
                    request.form.get("concept", "").strip() or "Cargo manual",
                    charge=amount
                )
                flash("Cargo agregado.", "success")

            elif action == "payment":
                create_account_movement(
                    client.id,
                    "ABONO",
                    request.form.get("concept", "").strip() or "Abono manual",
                    credit=amount
                )
                flash("Abono registrado.", "success")

            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(str(e), "danger")

        return redirect(url_for("client_detail", client_id=client.id))

    movements = AccountMovement.query.filter_by(client_id=client.id).order_by(AccountMovement.created_at.desc()).all()
    payments = Payment.query.filter_by(client_id=client.id).order_by(Payment.created_at.desc()).all()
    balance = client_balance(client.id)
    payment_url = url_for("public_payment", token=client.payment_token, _external=True)

    return page("""
    <div class="d-flex flex-wrap justify-content-between gap-3 align-items-start mb-4">
      <div>
        <div class="hero-title">{{ client.name }}</div>
        <div class="hero-sub">{{ client.phone or 'Sin teléfono' }} • {{ client.email or 'Sin correo' }}</div>
        <div class="hero-sub mt-1"><i class="bi bi-geo-alt"></i> {{ client.address or 'Sin dirección' }}</div>
      </div>
      <div class="panel p-3 text-end" style="min-width:210px">
        <div class="section-sub">Saldo pendiente</div>
        <div style="font-size:29px;font-weight:900" class="{{ 'debt' if balance>0 else 'credit' }}">{{ balance|money }}</div>
      </div>
    </div>

    <div class="panel p-4 mb-4">
      <div class="d-flex align-items-center gap-3 mb-3">
        <div class="avatar" style="background:linear-gradient(135deg,#ef4ba1,#7047ff)"><i class="bi bi-link-45deg"></i></div>
        <div><h2 class="section-title">Link de pago del cliente</h2><div class="section-sub">Compártelo para que suba su comprobante</div></div>
      </div>
      <div class="input-group">
        <input class="form-control" id="paymentLink" readonly value="{{ payment_url }}">
        <button class="btn btn-gradient" onclick="navigator.clipboard.writeText(document.getElementById('paymentLink').value)">
          <i class="bi bi-copy"></i> Copiar
        </button>
      </div>
    </div>

    <div class="row g-4">
      <div class="col-lg-4">
        <div class="panel p-4 mb-4">
          <h2 class="section-title mb-3 text-danger"><i class="bi bi-plus-circle me-1"></i> Aumentar deuda</h2>
          <form method="post">
            <input type="hidden" name="action" value="charge">
            <input class="form-control mb-3" type="number" step="0.01" min="0.01" name="amount" placeholder="Monto" required>
            <input class="form-control mb-3" name="concept" placeholder="Concepto">
            <button class="btn btn-danger w-100">Agregar cargo</button>
          </form>
        </div>

        <div class="panel p-4">
          <h2 class="section-title mb-3 text-success"><i class="bi bi-dash-circle me-1"></i> Reducir deuda</h2>
          <form method="post">
            <input type="hidden" name="action" value="payment">
            <input class="form-control mb-3" type="number" step="0.01" min="0.01" name="amount" placeholder="Monto" required>
            <input class="form-control mb-3" name="concept" placeholder="Concepto">
            <button class="btn btn-success w-100">Registrar abono</button>
          </form>
        </div>
      </div>

      <div class="col-lg-8">
        <div class="panel p-4 mb-4">
          <h2 class="section-title mb-3">Estado de cuenta</h2>
          <div class="table-responsive">
            <table class="table">
              <thead><tr><th>Fecha</th><th>Concepto</th><th>Cargo</th><th>Abono</th></tr></thead>
              <tbody>
              {% for m in movements %}
                <tr>
                  <td>{{ m.created_at.strftime('%d/%m/%Y') }}</td>
                  <td>{{ m.concept }}</td>
                  <td class="debt">{{ m.charge|money if m.charge else '-' }}</td>
                  <td class="credit">{{ m.credit|money if m.credit else '-' }}</td>
                </tr>
              {% else %}
                <tr><td colspan="4" class="text-center text-secondary py-4">Sin movimientos.</td></tr>
              {% endfor %}
              </tbody>
            </table>
          </div>
        </div>

        <div class="panel p-4">
          <h2 class="section-title mb-3">Comprobantes</h2>
          <div class="table-responsive">
            <table class="table">
              <thead><tr><th>Fecha</th><th>Monto</th><th>Referencia</th><th>Estado</th><th></th></tr></thead>
              <tbody>
              {% for p in payments %}
                <tr>
                  <td>{{ p.created_at.strftime('%d/%m/%Y %H:%M') }}</td>
                  <td>{{ p.amount|money }}</td>
                  <td>{{ p.reference or '-' }}</td>
                  <td>
                    <span class="badge rounded-pill text-bg-{{ 'success' if p.status=='APROBADO' else 'warning' if p.status=='PENDIENTE' else 'danger' }}">
                      {{ p.status }}
                    </span>
                  </td>
                  <td>
                    <div class="d-flex gap-1 flex-wrap">
                      {% if p.receipt_file %}
                        <a class="btn btn-sm btn-light" target="_blank" href="{{ url_for('uploaded_file', filename=p.receipt_file) }}"><i class="bi bi-eye"></i></a>
                      {% endif %}
                      {% if p.status == 'PENDIENTE' %}
                        <form method="post" action="{{ url_for('approve_payment', payment_id=p.id) }}">
                          <button class="btn btn-sm btn-success">Aprobar</button>
                        </form>
                        <form method="post" action="{{ url_for('reject_payment', payment_id=p.id) }}">
                          <button class="btn btn-sm btn-danger">Rechazar</button>
                        </form>
                      {% endif %}
                    </div>
                  </td>
                </tr>
              {% else %}
                <tr><td colspan="5" class="text-center text-secondary py-4">Sin comprobantes.</td></tr>
              {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """, title=client.name, active="clients", client=client, balance=balance,
         movements=movements, payments=payments, payment_url=payment_url)


@app.route("/pagos")
@login_required
def payments_admin():
    rows = Payment.query.order_by(Payment.created_at.desc()).all()
    return page("""
    <div class="mb-4">
      <div class="hero-title">Deudas y pagos</div>
      <div class="hero-sub">Revisa comprobantes y pagos enviados por tus clientes.</div>
    </div>

    <div class="panel p-4">
      <div class="table-responsive">
        <table class="table">
          <thead><tr><th>Cliente</th><th>Monto</th><th>Referencia</th><th>Fecha</th><th>Estado</th><th>Acciones</th></tr></thead>
          <tbody>
          {% for p in rows %}
            <tr>
              <td><strong>{{ p.client.name }}</strong></td>
              <td>{{ p.amount|money }}</td>
              <td>{{ p.reference or '-' }}</td>
              <td>{{ p.created_at.strftime('%d/%m/%Y %H:%M') }}</td>
              <td><span class="badge rounded-pill text-bg-{{ 'success' if p.status=='APROBADO' else 'warning' if p.status=='PENDIENTE' else 'danger' }}">{{ p.status }}</span></td>
              <td>
                <div class="d-flex gap-1 flex-wrap">
                  {% if p.receipt_file %}
                  <a class="btn btn-sm btn-light" target="_blank" href="{{ url_for('uploaded_file', filename=p.receipt_file) }}"><i class="bi bi-paperclip"></i></a>
                  {% endif %}
                  <a class="btn btn-sm btn-gradient" href="{{ url_for('client_detail', client_id=p.client_id) }}">Cliente</a>
                </div>
              </td>
            </tr>
          {% else %}
            <tr><td colspan="6" class="text-center text-secondary py-5">Sin pagos registrados.</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
    """, title="Pagos", active="payments", rows=rows)


@app.route("/pago/<token>", methods=["GET", "POST"])
def public_payment(token):
    client = Client.query.filter_by(payment_token=token, active=True).first_or_404()

    if request.method == "POST":
        try:
            amount = Decimal(request.form.get("amount", "0"))
            if amount <= 0:
                raise ValueError("El monto debe ser mayor a cero.")

            receipt = request.files.get("receipt")
            filename = save_upload(receipt) if receipt and receipt.filename else None

            payment = Payment(
                client_id=client.id,
                amount=amount,
                reference=request.form.get("reference", "").strip(),
                receipt_file=filename,
                status="PENDIENTE"
            )
            db.session.add(payment)
            db.session.commit()
            flash("Comprobante enviado. Queda pendiente de aprobación.", "success")
            return redirect(url_for("public_payment", token=token))

        except Exception as e:
            db.session.rollback()
            flash(str(e), "danger")

    balance = client_balance(client.id)

    return page("""
    <div class="login-page">
      <div class="panel p-4 p-md-5" style="width:min(610px,94vw)">
        <div class="d-flex align-items-center gap-3 mb-4">
          <div class="brand-mark">YM</div>
          <div>
            <div class="brand-title" style="color:#111827">YM Store</div>
            <div class="section-sub">Portal de pagos</div>
          </div>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
          {% for category, message in messages %}
            <div class="alert alert-{{ 'danger' if category=='danger' else category }}">{{ message }}</div>
          {% endfor %}
        {% endwith %}

        <div class="p-4 mb-4 rounded-4 text-white" style="background:linear-gradient(135deg,#5f3cff,#ef4ba1)">
          <div style="opacity:.85;font-size:12px">Cliente</div>
          <div class="fw-bold fs-4">{{ client.name }}</div>
          <div style="opacity:.85;font-size:12px;margin-top:14px">Saldo pendiente</div>
          <div style="font-size:32px;font-weight:900">{{ balance|money }}</div>
        </div>

        <form method="post" enctype="multipart/form-data">
          <label class="form-label fw-bold">Cantidad pagada</label>
          <input class="form-control mb-3" type="number" step="0.01" min="0.01" name="amount" required>

          <label class="form-label fw-bold">Referencia</label>
          <input class="form-control mb-3" name="reference" placeholder="Transferencia, depósito, etc.">

          <label class="form-label fw-bold">Comprobante</label>
          <input class="form-control mb-4" type="file" name="receipt" accept=".jpg,.jpeg,.png,.webp,.pdf">

          <button class="btn btn-gradient w-100 py-3"><i class="bi bi-cloud-arrow-up me-2"></i> Enviar comprobante</button>
        </form>
      </div>
    </div>
    """, title="Pago YM Store", client=client, balance=balance)


@app.route("/pagos/<int:payment_id>/aprobar", methods=["POST"])
@admin_required
def approve_payment(payment_id):
    payment = db.session.get(Payment, payment_id)
    if not payment:
        abort(404)

    if payment.status != "PENDIENTE":
        flash("Este pago ya fue procesado.", "warning")
        return redirect(url_for("client_detail", client_id=payment.client_id))

    create_account_movement(
        payment.client_id,
        "ABONO",
        f"Pago aprobado #{payment.id}",
        credit=payment.amount,
        reference=payment.reference
    )
    payment.status = "APROBADO"
    payment.approved_at = datetime.now()
    db.session.commit()

    flash("Pago aprobado y deuda actualizada.", "success")
    return redirect(url_for("client_detail", client_id=payment.client_id))


@app.route("/pagos/<int:payment_id>/rechazar", methods=["POST"])
@admin_required
def reject_payment(payment_id):
    payment = db.session.get(Payment, payment_id)
    if not payment:
        abort(404)

    if payment.status == "PENDIENTE":
        payment.status = "RECHAZADO"
        db.session.commit()

    flash("Pago rechazado.", "warning")
    return redirect(url_for("client_detail", client_id=payment.client_id))


@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ============================================================
# INVENTARIO
# ============================================================

@app.route("/productos", methods=["GET", "POST"])
@login_required
def products():
    if request.method == "POST":
        try:
            sku = request.form.get("sku", "").strip().upper()
            name = request.form.get("name", "").strip()

            if not sku or not name:
                raise ValueError("SKU y nombre son obligatorios.")

            product = Product(
                sku=sku,
                name=name,
                description=request.form.get("description", "").strip(),
                purchase_price=Decimal(request.form.get("purchase_price", "0")),
                sale_price=Decimal(request.form.get("sale_price", "0")),
                stock=int(request.form.get("stock", 0)),
                minimum_stock=int(request.form.get("minimum_stock", 0))
            )
            db.session.add(product)
            db.session.flush()

            if product.stock:
                add_inventory_movement(product, "ALTA_INICIAL", product.stock, reference="ALTA")

            db.session.commit()
            flash("Producto creado.", "success")
            return redirect(url_for("products"))

        except Exception as e:
            db.session.rollback()
            flash(f"No se pudo crear el producto: {e}", "danger")

    rows = Product.query.filter_by(active=True).order_by(Product.name).all()

    return page("""
    <div class="mb-4">
      <div class="hero-title">Inventario</div>
      <div class="hero-sub">Administra productos, precios y existencias.</div>
    </div>

    <div class="row g-4">
      <div class="col-lg-4">
        <div class="panel p-4">
          <div class="d-flex align-items-center gap-3 mb-4">
            <div class="avatar" style="background:linear-gradient(135deg,#7047ff,#ef4ba1)"><i class="bi bi-box-seam"></i></div>
            <div><h2 class="section-title">Nuevo producto</h2><div class="section-sub">Crea un artículo en inventario</div></div>
          </div>

          <form method="post">
            <input class="form-control mb-3" name="sku" placeholder="SKU / Código" required>
            <input class="form-control mb-3" name="name" placeholder="Nombre del producto" required>
            <textarea class="form-control mb-3" name="description" placeholder="Descripción"></textarea>
            <div class="row g-2">
              <div class="col-6"><input class="form-control" type="number" step="0.01" name="purchase_price" placeholder="Compra"></div>
              <div class="col-6"><input class="form-control" type="number" step="0.01" name="sale_price" placeholder="Venta"></div>
            </div>
            <div class="row g-2 mt-1">
              <div class="col-6"><input class="form-control" type="number" name="stock" value="0" placeholder="Stock"></div>
              <div class="col-6"><input class="form-control" type="number" name="minimum_stock" value="0" placeholder="Mínimo"></div>
            </div>
            <button class="btn btn-gradient w-100 mt-4">Guardar producto</button>
          </form>
        </div>
      </div>

      <div class="col-lg-8">
        <div class="panel p-4">
          <div class="d-flex justify-content-between mb-3">
            <div><h2 class="section-title">Existencias</h2><div class="section-sub">{{ rows|length }} productos activos</div></div>
          </div>

          <div class="table-responsive">
            <table class="table">
              <thead><tr><th>SKU</th><th>Producto</th><th>Compra</th><th>Venta</th><th>Stock</th><th>Ajustar</th></tr></thead>
              <tbody>
              {% for p in rows %}
                <tr>
                  <td><span class="badge-soft">{{ p.sku }}</span></td>
                  <td><strong>{{ p.name }}</strong><div class="section-sub">{{ p.description or '' }}</div></td>
                  <td>{{ p.purchase_price|money }}</td>
                  <td>{{ p.sale_price|money }}</td>
                  <td><span class="badge rounded-pill text-bg-{{ 'danger' if p.stock <= p.minimum_stock else 'success' }}">{{ p.stock }}</span></td>
                  <td>
                    <form class="d-flex gap-1" method="post" action="{{ url_for('adjust_stock', product_id=p.id) }}">
                      <input class="form-control form-control-sm" style="width:80px" type="number" name="quantity" required placeholder="+/-">
                      <button class="btn btn-sm btn-light"><i class="bi bi-check-lg"></i></button>
                    </form>
                  </td>
                </tr>
              {% else %}
                <tr><td colspan="6" class="text-center text-secondary py-5">Sin productos.</td></tr>
              {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """, title="Inventario", active="products", rows=rows)


@app.route("/productos/<int:product_id>/ajustar", methods=["POST"])
@login_required
def adjust_stock(product_id):
    product = db.session.get(Product, product_id)
    if not product:
        abort(404)

    try:
        qty = int(request.form.get("quantity", 0))
        if qty == 0:
            raise ValueError("La cantidad no puede ser cero.")
        if product.stock + qty < 0:
            raise ValueError("No hay suficiente stock.")

        product.stock += qty
        add_inventory_movement(
            product,
            "AJUSTE_ENTRADA" if qty > 0 else "AJUSTE_SALIDA",
            qty,
            reference="AJUSTE_MANUAL"
        )
        db.session.commit()
        flash("Stock actualizado.", "success")
    except Exception as e:
        db.session.rollback()
        flash(str(e), "danger")

    return redirect(url_for("products"))


# ============================================================
# COMPRAS
# ============================================================

@app.route("/compras", methods=["GET", "POST"])
@login_required
def purchases():
    products_list = Product.query.filter_by(active=True).order_by(Product.name).all()

    if request.method == "POST":
        try:
            product = db.session.get(Product, int(request.form["product_id"]))
            qty = int(request.form["quantity"])
            cost = Decimal(request.form["unit_cost"])
            supplier = request.form.get("supplier", "").strip() or "Proveedor"

            if not product or qty <= 0 or cost < 0:
                raise ValueError("Datos de compra inválidos.")

            total = cost * qty
            purchase = Purchase(supplier=supplier, total=total)
            db.session.add(purchase)
            db.session.flush()

            db.session.add(PurchaseItem(
                purchase_id=purchase.id,
                product_id=product.id,
                quantity=qty,
                unit_cost=cost,
                subtotal=total
            ))

            product.stock += qty
            product.purchase_price = cost
            add_inventory_movement(product, "COMPRA", qty, reference=f"COMPRA-{purchase.id}")

            db.session.commit()
            flash("Compra registrada y stock aumentado.", "success")
            return redirect(url_for("purchases"))

        except Exception as e:
            db.session.rollback()
            flash(str(e), "danger")

    rows = Purchase.query.order_by(Purchase.created_at.desc()).limit(100).all()

    return page("""
    <div class="mb-4">
      <div class="hero-title">Compras</div>
      <div class="hero-sub">Registra entradas de mercancía y costos de proveedores.</div>
    </div>

    <div class="row g-4">
      <div class="col-lg-4">
        <div class="panel p-4">
          <div class="d-flex align-items-center gap-3 mb-4">
            <div class="avatar" style="background:linear-gradient(135deg,#ef4ba1,#ff9d12)"><i class="bi bi-cart-plus"></i></div>
            <div><h2 class="section-title">Nueva compra</h2><div class="section-sub">Aumenta stock automáticamente</div></div>
          </div>
          <form method="post">
            <input class="form-control mb-3" name="supplier" placeholder="Proveedor">
            <select class="form-select mb-3" name="product_id" required>
              <option value="">Selecciona producto...</option>
              {% for p in products_list %}<option value="{{ p.id }}">{{ p.sku }} - {{ p.name }}</option>{% endfor %}
            </select>
            <input class="form-control mb-3" type="number" min="1" name="quantity" placeholder="Cantidad" required>
            <input class="form-control mb-4" type="number" step="0.01" min="0" name="unit_cost" placeholder="Costo unitario" required>
            <button class="btn btn-gradient w-100">Registrar compra</button>
          </form>
        </div>
      </div>

      <div class="col-lg-8">
        <div class="panel p-4">
          <h2 class="section-title mb-3">Historial de compras</h2>
          <div class="table-responsive">
            <table class="table">
              <thead><tr><th>#</th><th>Proveedor</th><th>Total</th><th>Fecha</th></tr></thead>
              <tbody>
              {% for r in rows %}
                <tr><td>#{{ r.id }}</td><td><strong>{{ r.supplier }}</strong></td><td>{{ r.total|money }}</td><td>{{ r.created_at.strftime('%d/%m/%Y %H:%M') }}</td></tr>
              {% else %}
                <tr><td colspan="4" class="text-center text-secondary py-5">Sin compras.</td></tr>
              {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """, title="Compras", active="purchases", rows=rows, products_list=products_list)


# ============================================================
# VENTAS
# ============================================================

@app.route("/ventas", methods=["GET", "POST"])
@login_required
def sales():
    clients_list = Client.query.filter_by(active=True).order_by(Client.name).all()
    products_list = Product.query.filter_by(active=True).order_by(Product.name).all()

    if request.method == "POST":
        try:
            client = db.session.get(Client, int(request.form["client_id"]))
            product = db.session.get(Product, int(request.form["product_id"]))
            qty = int(request.form["quantity"])
            price = Decimal(request.form.get("unit_price") or product.sale_price)
            paid_now = Decimal(request.form.get("paid_now") or 0)

            if not client or not product:
                raise ValueError("Cliente o producto inválido.")
            if qty <= 0:
                raise ValueError("Cantidad inválida.")
            if qty > product.stock:
                raise ValueError(f"Stock insuficiente. Disponible: {product.stock}")
            if price < 0 or paid_now < 0:
                raise ValueError("Los importes no pueden ser negativos.")

            total = price * qty
            if paid_now > total:
                raise ValueError("El pago inicial no puede ser mayor que la venta.")

            sale = Sale(
                client_id=client.id,
                total=total,
                paid_now=paid_now,
                status="PAGADA" if paid_now == total else "PENDIENTE"
            )
            db.session.add(sale)
            db.session.flush()

            db.session.add(SaleItem(
                sale_id=sale.id,
                product_id=product.id,
                quantity=qty,
                unit_price=price,
                subtotal=total
            ))

            product.stock -= qty
            add_inventory_movement(product, "VENTA", -qty, reference=f"VENTA-{sale.id}")

            create_account_movement(
                client.id,
                "CARGO",
                f"Venta #{sale.id} - {product.name}",
                charge=total,
                reference=f"VENTA-{sale.id}"
            )

            if paid_now > 0:
                create_account_movement(
                    client.id,
                    "ABONO",
                    f"Pago inicial venta #{sale.id}",
                    credit=paid_now,
                    reference=f"VENTA-{sale.id}"
                )

            db.session.commit()
            flash("Venta registrada. Inventario y deuda actualizados.", "success")
            return redirect(url_for("sales"))

        except Exception as e:
            db.session.rollback()
            flash(str(e), "danger")

    rows = Sale.query.order_by(Sale.created_at.desc()).limit(100).all()

    return page("""
    <div class="mb-4">
      <div class="hero-title">Ventas</div>
      <div class="hero-sub">Registra ventas y actualiza automáticamente deuda e inventario.</div>
    </div>

    <div class="row g-4">
      <div class="col-lg-4">
        <div class="panel p-4">
          <div class="d-flex align-items-center gap-3 mb-4">
            <div class="avatar" style="background:linear-gradient(135deg,#15bb75,#1795f5)"><i class="bi bi-bag-check"></i></div>
            <div><h2 class="section-title">Nueva venta</h2><div class="section-sub">Venta rápida a cliente</div></div>
          </div>
          <form method="post">
            <select class="form-select mb-3" name="client_id" required>
              <option value="">Cliente...</option>
              {% for c in clients_list %}<option value="{{ c.id }}">{{ c.name }}</option>{% endfor %}
            </select>
            <select class="form-select mb-3" name="product_id" required>
              <option value="">Producto...</option>
              {% for p in products_list %}<option value="{{ p.id }}">{{ p.sku }} - {{ p.name }} (Stock {{ p.stock }})</option>{% endfor %}
            </select>
            <input class="form-control mb-3" type="number" min="1" name="quantity" placeholder="Cantidad" required>
            <input class="form-control mb-3" type="number" step="0.01" min="0" name="unit_price" placeholder="Precio unitario (vacío = precio producto)">
            <input class="form-control mb-4" type="number" step="0.01" min="0" name="paid_now" placeholder="Pago inicial">
            <button class="btn btn-gradient w-100">Registrar venta</button>
          </form>
        </div>
      </div>

      <div class="col-lg-8">
        <div class="panel p-4">
          <h2 class="section-title mb-3">Ventas recientes</h2>
          <div class="table-responsive">
            <table class="table">
              <thead><tr><th>#</th><th>Cliente</th><th>Total</th><th>Pago inicial</th><th>Estado</th><th>Fecha</th></tr></thead>
              <tbody>
              {% for r in rows %}
                <tr>
                  <td>#{{ r.id }}</td>
                  <td><strong>{{ r.client.name }}</strong></td>
                  <td>{{ r.total|money }}</td>
                  <td>{{ r.paid_now|money }}</td>
                  <td><span class="badge rounded-pill text-bg-{{ 'success' if r.status=='PAGADA' else 'warning' }}">{{ r.status }}</span></td>
                  <td>{{ r.created_at.strftime('%d/%m/%Y') }}</td>
                </tr>
              {% else %}
                <tr><td colspan="6" class="text-center text-secondary py-5">Sin ventas.</td></tr>
              {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """, title="Ventas", active="sales", rows=rows, clients_list=clients_list, products_list=products_list)


# ============================================================
# TANDAS
# ============================================================

@app.route("/tandas", methods=["GET", "POST"])
@login_required
def tandas():
    if request.method == "POST":
        try:
            tanda = Tanda(
                name=request.form.get("name", "").strip(),
                amount=Decimal(request.form.get("amount", "0")),
                payment_amount=Decimal(request.form.get("payment_amount", "0")),
                frequency=request.form.get("frequency", "SEMANAL"),
                start_date=datetime.strptime(request.form.get("start_date"), "%Y-%m-%d").date()
            )
            if not tanda.name or tanda.amount <= 0 or tanda.payment_amount <= 0:
                raise ValueError("Datos de tanda inválidos.")

            db.session.add(tanda)
            db.session.commit()
            flash("Tanda creada.", "success")
            return redirect(url_for("tanda_detail", tanda_id=tanda.id))
        except Exception as e:
            db.session.rollback()
            flash(str(e), "danger")

    rows = Tanda.query.order_by(Tanda.created_at.desc()).all()

    return page("""
    <div class="mb-4">
      <div class="hero-title">Tandas</div>
      <div class="hero-sub">Organiza participantes, turnos y pagos.</div>
    </div>

    <div class="row g-4">
      <div class="col-lg-4">
        <div class="panel p-4">
          <div class="d-flex align-items-center gap-3 mb-4">
            <div class="avatar" style="background:linear-gradient(135deg,#ff9d12,#ef4ba1)"><i class="bi bi-coin"></i></div>
            <div><h2 class="section-title">Nueva tanda</h2><div class="section-sub">Crea un nuevo grupo</div></div>
          </div>
          <form method="post">
            <input class="form-control mb-3" name="name" placeholder="Nombre de la tanda" required>
            <input class="form-control mb-3" type="number" step="0.01" min="0.01" name="amount" placeholder="Monto total" required>
            <input class="form-control mb-3" type="number" step="0.01" min="0.01" name="payment_amount" placeholder="Pago periódico" required>
            <select class="form-select mb-3" name="frequency">
              <option>SEMANAL</option><option>QUINCENAL</option><option>MENSUAL</option>
            </select>
            <input class="form-control mb-4" type="date" name="start_date" value="{{ today }}" required>
            <button class="btn btn-gradient w-100">Crear tanda</button>
          </form>
        </div>
      </div>

      <div class="col-lg-8">
        <div class="panel p-4">
          <h2 class="section-title mb-3">Tandas registradas</h2>
          <div class="table-responsive">
            <table class="table">
              <thead><tr><th>Nombre</th><th>Monto</th><th>Pago</th><th>Frecuencia</th><th>Estado</th><th></th></tr></thead>
              <tbody>
              {% for t in rows %}
                <tr>
                  <td><strong>{{ t.name }}</strong></td>
                  <td>{{ t.amount|money }}</td>
                  <td>{{ t.payment_amount|money }}</td>
                  <td>{{ t.frequency }}</td>
                  <td><span class="badge rounded-pill text-bg-success">{{ t.status }}</span></td>
                  <td><a class="btn btn-sm btn-gradient" href="{{ url_for('tanda_detail', tanda_id=t.id) }}">Abrir</a></td>
                </tr>
              {% else %}
                <tr><td colspan="6" class="text-center text-secondary py-5">Sin tandas.</td></tr>
              {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """, title="Tandas", active="tandas", rows=rows, today=date.today().isoformat())


@app.route("/tandas/<int:tanda_id>", methods=["GET", "POST"])
@login_required
def tanda_detail(tanda_id):
    tanda = db.session.get(Tanda, tanda_id)
    if not tanda:
        abort(404)

    if request.method == "POST":
        action = request.form.get("action")

        try:
            if action == "add_participant":
                client_id = int(request.form["client_id"])
                turn = int(request.form["turn_number"])
                total_due = Decimal(request.form.get("total_due") or tanda.amount)

                exists = TandaParticipant.query.filter_by(
                    tanda_id=tanda.id,
                    client_id=client_id
                ).first()
                if exists:
                    raise ValueError("El cliente ya participa en esta tanda.")

                db.session.add(TandaParticipant(
                    tanda_id=tanda.id,
                    client_id=client_id,
                    turn_number=turn,
                    total_due=total_due
                ))
                db.session.commit()
                flash("Participante agregado.", "success")

            elif action == "payment":
                participant = db.session.get(
                    TandaParticipant,
                    int(request.form["participant_id"])
                )
                amount = Decimal(request.form["amount"])

                if not participant or participant.tanda_id != tanda.id:
                    raise ValueError("Participante inválido.")
                if amount <= 0:
                    raise ValueError("Monto inválido.")

                filename = None
                receipt = request.files.get("receipt")
                if receipt and receipt.filename:
                    filename = save_upload(receipt)

                db.session.add(TandaPayment(
                    participant_id=participant.id,
                    amount=amount,
                    receipt_file=filename,
                    notes=request.form.get("notes", "").strip()
                ))

                participant.paid = Decimal(participant.paid or 0) + amount
                participant.status = "PAGADO" if participant.paid >= participant.total_due else "PENDIENTE"

                create_account_movement(
                    participant.client_id,
                    "ABONO",
                    f"Pago tanda {tanda.name}",
                    credit=amount,
                    reference=f"TANDA-{tanda.id}"
                )

                db.session.commit()
                flash("Pago de tanda registrado.", "success")

        except Exception as e:
            db.session.rollback()
            flash(str(e), "danger")

        return redirect(url_for("tanda_detail", tanda_id=tanda.id))

    clients_list = Client.query.filter_by(active=True).order_by(Client.name).all()
    participants = TandaParticipant.query.filter_by(
        tanda_id=tanda.id
    ).order_by(TandaParticipant.turn_number).all()

    return page("""
    <div class="d-flex flex-wrap justify-content-between align-items-start gap-3 mb-4">
      <div>
        <div class="hero-title">{{ tanda.name }}</div>
        <div class="hero-sub">{{ tanda.frequency }} • Inicio {{ tanda.start_date.strftime('%d/%m/%Y') }}</div>
      </div>
      <div class="panel p-3">
        <div class="section-sub">Pago periódico</div>
        <div style="font-size:24px;font-weight:900;color:#7047ff">{{ tanda.payment_amount|money }}</div>
      </div>
    </div>

    <div class="row g-4">
      <div class="col-lg-4">
        <div class="panel p-4 mb-4">
          <h2 class="section-title mb-3">Agregar participante</h2>
          <form method="post">
            <input type="hidden" name="action" value="add_participant">
            <select class="form-select mb-3" name="client_id" required>
              <option value="">Cliente...</option>
              {% for c in clients_list %}<option value="{{ c.id }}">{{ c.name }}</option>{% endfor %}
            </select>
            <input class="form-control mb-3" type="number" min="1" name="turn_number" placeholder="Turno" required>
            <input class="form-control mb-4" type="number" step="0.01" min="0" name="total_due" value="{{ tanda.amount }}" required>
            <button class="btn btn-gradient w-100">Agregar participante</button>
          </form>
        </div>

        <div class="panel p-4">
          <h2 class="section-title mb-3">Registrar pago</h2>
          <form method="post" enctype="multipart/form-data">
            <input type="hidden" name="action" value="payment">
            <select class="form-select mb-3" name="participant_id" required>
              <option value="">Participante...</option>
              {% for p in participants %}<option value="{{ p.id }}">{{ p.client.name }}</option>{% endfor %}
            </select>
            <input class="form-control mb-3" type="number" step="0.01" min="0.01" name="amount" placeholder="Monto" required>
            <input class="form-control mb-3" name="notes" placeholder="Notas">
            <input class="form-control mb-4" type="file" name="receipt" accept=".jpg,.jpeg,.png,.webp,.pdf">
            <button class="btn btn-success w-100">Registrar pago</button>
          </form>
        </div>
      </div>

      <div class="col-lg-8">
        <div class="panel p-4">
          <h2 class="section-title mb-3">Participantes</h2>
          <div class="table-responsive">
            <table class="table">
              <thead><tr><th>Turno</th><th>Cliente</th><th>Debe</th><th>Pagado</th><th>Pendiente</th><th>Estado</th></tr></thead>
              <tbody>
              {% for p in participants %}
                <tr>
                  <td><span class="badge-soft">#{{ p.turn_number }}</span></td>
                  <td><strong>{{ p.client.name }}</strong></td>
                  <td>{{ p.total_due|money }}</td>
                  <td class="credit">{{ p.paid|money }}</td>
                  <td class="debt">{{ (p.total_due - p.paid)|money }}</td>
                  <td><span class="badge rounded-pill text-bg-{{ 'success' if p.status=='PAGADO' else 'warning' }}">{{ p.status }}</span></td>
                </tr>
              {% else %}
                <tr><td colspan="6" class="text-center text-secondary py-5">Sin participantes.</td></tr>
              {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """, title=tanda.name, active="tandas", tanda=tanda,
         clients_list=clients_list, participants=participants)


# ============================================================
# INIT / ERRORS
# ============================================================

def create_default_admin():
    if not User.query.filter_by(username="admin").first():
        admin = User(
            name=os.getenv("ADMIN_NAME", "Yajaira Moreno"),
            username="admin",
            role="ADMIN"
        )
        admin.set_password(os.getenv("ADMIN_PASSWORD", "Admin1234!"))
        db.session.add(admin)
        db.session.commit()
        print("Usuario inicial creado: admin")
        print("Contraseña inicial: Admin1234!")
        print("IMPORTANTE: cámbiala antes de publicar la aplicación.")


@app.errorhandler(403)
def forbidden(_):
    return page("""
    <div class="panel p-5 text-center">
      <div style="font-size:60px">🔒</div>
      <h1 class="fw-bold mt-3">Acceso denegado</h1>
      <p class="text-secondary">No tienes permiso para realizar esta acción.</p>
    </div>
    """, title="Acceso denegado"), 403


@app.errorhandler(404)
def not_found(_):
    return page("""
    <div class="panel p-5 text-center">
      <div style="font-size:60px">🧭</div>
      <h1 class="fw-bold mt-3">Página no encontrada</h1>
      <a class="btn btn-gradient mt-3" href="{{ url_for('dashboard') }}">Volver al inicio</a>
    </div>
    """, title="404"), 404


@app.errorhandler(413)
def too_large(_):
    flash("El archivo supera el límite permitido de 8 MB.", "danger")
    return redirect(request.referrer or url_for("dashboard"))


with app.app_context():
    db.create_all()
    create_default_admin()


if __name__ == "__main__":
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", 5000)),
        debug=os.getenv("FLASK_DEBUG", "1") == "1"
    )