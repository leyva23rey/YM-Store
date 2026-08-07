import os
import secrets
from io import BytesIO
from datetime import datetime, date, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, redirect, url_for, flash, session,
    send_from_directory, send_file, abort, render_template_string
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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

# Entorno seguro: Render se considera producción automáticamente.
APP_ENV = os.getenv("APP_ENV", "development").lower()
IS_PRODUCTION = APP_ENV == "production" or os.getenv("RENDER", "").lower() == "true"

secret_key = os.getenv("SECRET_KEY")
if IS_PRODUCTION and not secret_key:
    raise RuntimeError("SECRET_KEY es obligatoria en producción. Configúrala como variable de entorno.")
app.config["SECRET_KEY"] = secret_key or secrets.token_hex(32)

raw_database_url = os.getenv("DATABASE_URL")
if IS_PRODUCTION and not raw_database_url:
    raise RuntimeError("DATABASE_URL es obligatoria en producción. Usa PostgreSQL; no publiques con SQLite.")
if not raw_database_url:
    raw_database_url = "sqlite:///" + str(BASE_DIR / "ym_store.db")
if raw_database_url.startswith("postgres://"):
    raw_database_url = raw_database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif raw_database_url.startswith("postgresql://"):
    raw_database_url = raw_database_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config.update(
    SQLALCHEMY_DATABASE_URI=raw_database_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,
    UPLOAD_FOLDER=str(UPLOAD_DIR),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    WTF_CSRF_TIME_LIMIT=7200,
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
    default_limits=[]
)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "pdf"}
ALLOWED_MIME_TYPES = {
    "png": {"image/png"},
    "jpg": {"image/jpeg"},
    "jpeg": {"image/jpeg"},
    "webp": {"image/webp"},
    "pdf": {"application/pdf"},
}


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


def get_customer_profile():
    user = current_user()
    if not user or user.role != "CLIENTE":
        return None
    return CustomerProfile.query.filter_by(user_id=user.id).first()


def customer_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Inicia sesión para continuar.", "warning")
            return redirect(url_for("login"))
        if user.role != "CLIENTE":
            abort(403)
        if not get_customer_profile():
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def user_home_url(user=None):
    user = user or current_user()
    if not user:
        return url_for("store")
    return url_for("dashboard") if user.role == "ADMIN" else url_for("customer_home")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _valid_file_signature(ext, header):
    if ext == "png":
        return header.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in {"jpg", "jpeg"}:
        return header.startswith(b"\xff\xd8\xff")
    if ext == "pdf":
        return header.startswith(b"%PDF-")
    if ext == "webp":
        return len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP"
    return False


def save_upload(file_storage):
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename):
        raise ValueError("Formato no permitido. Usa JPG, PNG, WEBP o PDF.")

    original = secure_filename(file_storage.filename)
    ext = original.rsplit(".", 1)[1].lower()
    if file_storage.mimetype not in ALLOWED_MIME_TYPES.get(ext, set()):
        raise ValueError("El tipo real del archivo no coincide con su extensión.")

    header = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    if not _valid_file_signature(ext, header):
        raise ValueError("El contenido del archivo no es válido o fue alterado.")

    filename = f"{datetime.now():%Y%m%d%H%M%S}_{secrets.token_hex(16)}.{ext}"
    destination = UPLOAD_DIR / filename
    file_storage.save(destination)
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass
    return filename


def product_image_payload(file_storage):
    """Valida una imagen de catálogo y devuelve bytes seguros para PostgreSQL."""
    if not file_storage or not file_storage.filename:
        return None

    original = secure_filename(file_storage.filename)
    if "." not in original:
        raise ValueError("La imagen necesita una extensión válida.")

    ext = original.rsplit(".", 1)[1].lower()
    if ext not in {"png", "jpg", "jpeg", "webp"}:
        raise ValueError("La foto del producto debe ser JPG, PNG o WEBP.")

    allowed_mimes = {
        "png": {"image/png"},
        "jpg": {"image/jpeg"},
        "jpeg": {"image/jpeg"},
        "webp": {"image/webp"},
    }
    if file_storage.mimetype not in allowed_mimes[ext]:
        raise ValueError("El tipo de la imagen no coincide con su extensión.")

    data = file_storage.read(3 * 1024 * 1024 + 1)
    file_storage.stream.seek(0)
    if len(data) > 3 * 1024 * 1024:
        raise ValueError("La foto del producto no puede superar 3 MB.")

    if not _valid_file_signature(ext, data[:16]):
        raise ValueError("La foto del producto no parece ser una imagen válida.")

    return {
        "data": data,
        "mime_type": file_storage.mimetype,
        "filename": original[:180],
    }


def promotion_is_active(promo, now=None):
    if not promo or not promo.active:
        return False
    now = now or datetime.now()
    if promo.starts_at and now < promo.starts_at:
        return False
    if promo.ends_at and now > promo.ends_at:
        return False
    return True


def effective_product_price(product):
    promo = getattr(product, "promotion", None)
    if promotion_is_active(promo):
        return Decimal(promo.promo_price or 0)
    return Decimal(product.sale_price or 0)


def parse_optional_datetime(value):
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M")
    except ValueError:
        raise ValueError("La fecha de promoción no tiene un formato válido.")


def safe_form_error(exc, fallback="No se pudo completar la operación."):
    db.session.rollback()
    if isinstance(exc, (ValueError, InvalidOperation, KeyError)):
        flash(str(exc), "danger")
    else:
        app.logger.exception("Error interno durante una operación", exc_info=exc)
        flash(fallback, "danger")


def validate_text(value, field, max_length, required=False):
    value = (value or "").strip()
    if required and not value:
        raise ValueError(f"{field} es obligatorio.")
    if len(value) > max_length:
        raise ValueError(f"{field} supera el tamaño permitido ({max_length} caracteres).")
    return value


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


class CustomerProfile(db.Model):
    """Vincula una cuenta de acceso CLIENTE con su ficha comercial."""
    __tablename__ = "customer_profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True, index=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    user = db.relationship("User")
    client = db.relationship("Client")


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(80), nullable=False)
    entity_type = db.Column(db.String(80), nullable=False)
    entity_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.String(255))
    ip_address = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)


def audit(action, entity_type, entity_id=None, details=None):
    user = current_user()
    db.session.add(AuditLog(
        user_id=user.id if user else None,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=(details or "")[:255],
        ip_address=(request.remote_addr or "")[:64],
    ))


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


class ProductImage(db.Model):
    """
    Imagen pública del producto.
    Se guarda en PostgreSQL para que no se pierda en redeploys de Render.
    """
    __tablename__ = "product_images"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, unique=True, index=True)
    image_data = db.Column(db.LargeBinary, nullable=False)
    mime_type = db.Column(db.String(50), nullable=False)
    filename = db.Column(db.String(180), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    product = db.relationship(
        "Product",
        backref=db.backref("catalog_image", uselist=False, cascade="all, delete-orphan")
    )


class ProductPromotion(db.Model):
    """Promoción opcional del producto sin alterar la tabla products existente."""
    __tablename__ = "product_promotions"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, unique=True, index=True)
    label = db.Column(db.String(80), nullable=False, default="PROMOCIÓN")
    promo_price = db.Column(db.Numeric(12, 2), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    starts_at = db.Column(db.DateTime, nullable=True)
    ends_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)

    product = db.relationship(
        "Product",
        backref=db.backref("promotion", uselist=False, cascade="all, delete-orphan")
    )


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


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(self)"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com data:; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "connect-src 'self' https://api.open-meteo.com; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.endpoint not in {"uploaded_file", "product_image_file"}:
        response.headers.setdefault("Cache-Control", "no-store")
    return response


# ============================================================
# UI
# ============================================================

BASE_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>YM Store</title>
  <link rel="icon" type="image/png" href="{{ url_for('static', filename='ym-logo.png') }}">
  <link rel="apple-touch-icon" href="{{ url_for('static', filename='ym-logo.png') }}">

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

  <style>
    :root{
      --navy:#07101f;
      --navy-2:#101a32;
      --surface:rgba(255,255,255,.92);
      --bg:#f4f7fb;
      --text:#121829;
      --muted:#7b8497;
      --purple:#6d4aff;
      --purple-2:#8f65ff;
      --pink:#ff4f9f;
      --blue:#168df0;
      --green:#16b97b;
      --orange:#ff9e18;
      --cyan:#14c9c4;
      --danger:#ff4f64;
      --line:#e9edf5;
      --shadow:0 18px 50px rgba(21,31,54,.08);
      --shadow-hover:0 22px 60px rgba(21,31,54,.13);
      --radius:24px;
    }

    *{box-sizing:border-box}
    html{scroll-behavior:smooth}
    body{
      margin:0;
      min-height:100vh;
      font-family:'Inter',system-ui,-apple-system,sans-serif;
      background:
        radial-gradient(circle at 18% 8%, rgba(109,74,255,.07), transparent 25%),
        radial-gradient(circle at 92% 12%, rgba(255,79,159,.06), transparent 20%),
        linear-gradient(180deg,#f8faff 0%,#f3f6fb 100%);
      color:var(--text);
      -webkit-font-smoothing:antialiased;
    }

    a{text-decoration:none}
    .app-shell{min-height:100vh}

    .sidebar{
      position:fixed;
      inset:0 auto 0 0;
      width:258px;
      padding:20px 14px;
      background:
        radial-gradient(circle at 20% 5%, rgba(109,74,255,.28), transparent 26%),
        radial-gradient(circle at 100% 82%, rgba(22,141,240,.12), transparent 24%),
        linear-gradient(180deg,#08101f 0%,#0b1328 55%,#091020 100%);
      color:#dce5ff;
      overflow-y:auto;
      z-index:1000;
      border-right:1px solid rgba(255,255,255,.06);
      box-shadow:18px 0 50px rgba(5,10,24,.08);
    }

    .sidebar::-webkit-scrollbar{width:6px}
    .sidebar::-webkit-scrollbar-thumb{background:rgba(255,255,255,.12);border-radius:999px}

    .brand{
      display:flex;
      align-items:center;
      gap:13px;
      padding:5px 8px 24px;
    }

    .brand-mark{
      width:54px;height:54px;
      border-radius:18px;
      display:grid;place-items:center;
      font-weight:900;
      font-size:20px;
      letter-spacing:-1.5px;
      color:#fff;
      background:linear-gradient(135deg,#ffae28 0%,#ff4f9f 30%,#7650ff 62%,#1699f4 100%);
      box-shadow:0 14px 34px rgba(109,74,255,.38);
      position:relative;
      overflow:hidden;
      isolation:isolate;
    }

    .brand-mark::before{
      content:"";
      position:absolute;
      width:48px;height:48px;
      border:8px solid rgba(255,255,255,.14);
      border-radius:50%;
      left:-25px;bottom:-27px;
      z-index:-1;
    }

    .brand-mark::after{
      content:"";
      position:absolute;
      width:30px;height:30px;
      border:4px solid rgba(255,255,255,.20);
      border-radius:50%;
      right:-9px;top:-9px;
      z-index:-1;
    }

    .brand-title{font-weight:900;font-size:20px;letter-spacing:.1px;color:#fff}
    .brand-sub{font-size:10px;color:#8d9aba;margin-top:3px;letter-spacing:.25px}

    .nav-section{
      font-size:9px;
      text-transform:uppercase;
      letter-spacing:1.6px;
      color:#687795;
      margin:20px 13px 9px;
      font-weight:800;
    }

    .side-link{
      color:#cfd8ed;
      padding:12px 13px;
      display:flex;
      align-items:center;
      gap:12px;
      border-radius:14px;
      margin-bottom:5px;
      font-size:13px;
      font-weight:650;
      transition:all .2s ease;
      border:1px solid transparent;
    }

    .side-link i{
      font-size:17px;
      width:22px;
      text-align:center;
      opacity:.92;
    }

    .side-link:hover{
      color:#fff;
      background:rgba(255,255,255,.065);
      border-color:rgba(255,255,255,.04);
      transform:translateX(3px);
    }

    .side-link.active{
      color:#fff;
      background:linear-gradient(135deg,rgba(95,60,255,.96),rgba(129,77,255,.96));
      border-color:rgba(255,255,255,.10);
      box-shadow:0 12px 30px rgba(92,59,255,.30);
    }

    .side-user{
      margin-top:22px;
      padding:14px;
      border-radius:18px;
      background:linear-gradient(145deg,rgba(255,255,255,.07),rgba(255,255,255,.035));
      border:1px solid rgba(255,255,255,.07);
      backdrop-filter:blur(10px);
    }

    .avatar{
      width:42px;height:42px;
      display:grid;place-items:center;
      border-radius:14px;
      background:linear-gradient(135deg,#ff9e18,#ef4ba1 48%,#7047ff);
      color:white;
      font-weight:900;
      box-shadow:0 8px 20px rgba(112,71,255,.18);
    }

    .main{
      margin-left:258px;
      min-height:100vh;
    }

    .topbar{
      height:78px;
      background:rgba(255,255,255,.78);
      backdrop-filter:blur(18px);
      -webkit-backdrop-filter:blur(18px);
      border-bottom:1px solid rgba(228,233,242,.82);
      display:flex;
      align-items:center;
      justify-content:space-between;
      padding:0 30px;
      position:sticky;
      top:0;
      z-index:900;
      box-shadow:0 5px 26px rgba(20,30,55,.035);
    }

    .searchbox{
      width:min(470px,45vw);
      position:relative;
    }

    .searchbox input{
      width:100%;
      border:1px solid #e6eaf1;
      background:rgba(255,255,255,.88);
      border-radius:15px;
      padding:12px 46px 12px 16px;
      outline:none;
      font-size:13px;
      color:#6f798d;
      box-shadow:0 6px 22px rgba(15,23,42,.035);
    }

    .searchbox i{
      position:absolute;
      right:16px;top:50%;
      transform:translateY(-50%);
      color:#758097;
    }

    .content{
      padding:30px;
      max-width:1750px;
      margin:0 auto;
    }

    .hero-title{
      font-size:28px;
      font-weight:900;
      letter-spacing:-.8px;
      margin-bottom:5px;
      color:#111729;
    }

    .hero-sub{color:var(--muted);font-size:13px}

    .panel{
      background:var(--surface);
      border:1px solid rgba(231,235,243,.9);
      border-radius:var(--radius);
      box-shadow:var(--shadow);
      backdrop-filter:blur(10px);
      transition:box-shadow .22s ease,transform .22s ease,border-color .22s ease;
    }

    .panel:hover{
      box-shadow:var(--shadow-hover);
      border-color:#e1e6f1;
    }

    .stat-card{
      border-radius:22px;
      padding:21px;
      color:#fff;
      min-height:138px;
      position:relative;
      overflow:hidden;
      box-shadow:0 16px 34px rgba(25,32,56,.13);
      isolation:isolate;
      transition:transform .2s ease,box-shadow .2s ease;
    }

    .stat-card:hover{
      transform:translateY(-4px);
      box-shadow:0 22px 44px rgba(25,32,56,.17);
    }

    .stat-card::before{
      content:"";
      position:absolute;
      width:150px;height:150px;
      border-radius:50%;
      background:rgba(255,255,255,.08);
      right:-42px;top:-54px;
      z-index:-1;
    }

    .stat-card::after{
      content:"";
      position:absolute;
      width:82px;height:82px;
      border-radius:50%;
      border:16px solid rgba(255,255,255,.08);
      right:24px;bottom:-47px;
      z-index:-1;
    }

    .stat-purple{background:linear-gradient(135deg,#6240f6,#8b59ff)}
    .stat-green{background:linear-gradient(135deg,#0eac6a,#22cf8b)}
    .stat-orange{background:linear-gradient(135deg,#ff9215,#ffbc25)}
    .stat-blue{background:linear-gradient(135deg,#0a88e5,#2868ef)}
    .stat-pink{background:linear-gradient(135deg,#df4198,#f564b6)}

    .stat-label{font-size:11px;font-weight:700;opacity:.92;letter-spacing:.1px}
    .stat-value{font-size:27px;font-weight:900;margin-top:11px;letter-spacing:-.9px}
    .stat-foot{font-size:10.5px;margin-top:10px;opacity:.88}
    .stat-icon{
      position:absolute;
      right:18px;bottom:18px;
      width:48px;height:48px;border-radius:15px;
      background:rgba(255,255,255,.90);
      display:grid;place-items:center;
      color:#29314c;font-size:21px;
      z-index:2;
      box-shadow:0 9px 22px rgba(0,0,0,.08);
    }

    .section-title{font-size:15px;font-weight:850;margin:0;letter-spacing:-.15px}
    .section-sub{font-size:11.5px;color:var(--muted);margin-top:2px}

    .quick{
      min-height:112px;
      border-radius:20px;
      padding:17px;
      color:#fff;
      display:flex;
      flex-direction:column;
      justify-content:space-between;
      font-weight:800;
      box-shadow:0 12px 24px rgba(30,40,60,.08);
      transition:transform .2s ease,box-shadow .2s ease,filter .2s ease;
      overflow:hidden;
      position:relative;
    }

    .quick::after{
      content:"";
      position:absolute;
      width:70px;height:70px;
      right:-20px;top:-20px;
      border-radius:50%;
      background:rgba(255,255,255,.12);
    }

    .quick:hover{
      transform:translateY(-5px);
      color:#fff;
      filter:saturate(1.05);
      box-shadow:0 18px 34px rgba(30,40,60,.14);
    }

    .quick i{font-size:27px}

    .table{
      --bs-table-bg:transparent;
      margin-bottom:0;
    }

    .table thead th{
      color:#818a9e;
      font-size:10px;
      text-transform:uppercase;
      letter-spacing:.75px;
      border-bottom:1px solid #ebeff5;
      padding:13px 12px;
      white-space:nowrap;
      font-weight:800;
    }

    .table tbody tr{
      transition:background .16s ease;
    }

    .table tbody tr:hover{
      background:rgba(109,74,255,.028);
    }

    .table tbody td{
      padding:14px 12px;
      border-color:#f0f2f7;
      vertical-align:middle;
      font-size:12.5px;
    }

    .form-label{
      font-size:12px;
      color:#4c566d;
    }

    .form-control,.form-select{
      border-radius:14px;
      padding:11.5px 13px;
      border:1px solid #dfe5ef;
      font-size:13px;
      background:#fbfcfe;
      transition:border-color .18s ease,box-shadow .18s ease,background .18s ease;
    }

    .form-control:hover,.form-select:hover{background:#fff}

    .form-control:focus,.form-select:focus{
      background:#fff;
      border-color:#8a69ff;
      box-shadow:0 0 0 .22rem rgba(112,71,255,.11);
    }

    .input-group-text{
      border-color:#dfe5ef;
      border-radius:14px 0 0 14px;
      color:#7b8497;
    }

    .btn{
      border-radius:13px;
      font-weight:750;
      font-size:12.5px;
      padding:10px 15px;
      transition:all .18s ease;
    }

    .btn:hover{transform:translateY(-1px)}

    .btn-gradient{
      color:#fff;
      border:0;
      background:linear-gradient(135deg,#6140f8,#8955ff);
      box-shadow:0 9px 22px rgba(112,71,255,.25);
    }

    .btn-gradient:hover{
      color:#fff;
      box-shadow:0 12px 27px rgba(112,71,255,.34);
      filter:brightness(1.03);
    }

    .badge-soft{
      background:linear-gradient(135deg,#f2efff,#eef5ff);
      color:#6842ef;
      border:1px solid #e5defe;
      border-radius:999px;
      padding:7px 11px;
      font-weight:800;
      font-size:10.5px;
    }

    .debt{color:#e43f57;font-weight:850}
    .credit{color:#0da56a;font-weight:850}

    .login-page{
      min-height:100vh;
      background:
        radial-gradient(circle at 12% 15%, rgba(109,74,255,.15), transparent 26%),
        radial-gradient(circle at 86% 12%, rgba(255,79,159,.13), transparent 25%),
        radial-gradient(circle at 75% 85%, rgba(22,141,240,.12), transparent 25%),
        linear-gradient(135deg,#f7f8fe,#eef3fa);
      display:grid;
      place-items:center;
      padding:22px;
    }

    .login-card{
      width:min(980px,96vw);
      overflow:hidden;
      border-radius:30px;
      background:rgba(255,255,255,.94);
      box-shadow:0 34px 90px rgba(30,41,59,.17);
      display:grid;
      grid-template-columns:1.05fr .95fr;
      border:1px solid rgba(255,255,255,.8);
    }

    .login-brand{
      min-height:590px;
      padding:56px;
      color:#fff;
      background:
        radial-gradient(circle at 76% 13%, rgba(255,255,255,.14), transparent 23%),
        radial-gradient(circle at 18% 88%, rgba(23,149,245,.12), transparent 25%),
        linear-gradient(145deg,#07101f,#121b3b 56%,#2b1a70);
      display:flex;
      flex-direction:column;
      justify-content:space-between;
      position:relative;
      overflow:hidden;
    }

    .login-brand::after{
      content:"";
      position:absolute;
      width:260px;height:260px;
      border:45px solid rgba(255,255,255,.035);
      border-radius:50%;
      right:-110px;bottom:-100px;
    }

    .login-form{
      padding:60px 56px;
      align-self:center;
    }

    .login-logo{
      width:94px;height:94px;border-radius:28px;
      display:grid;place-items:center;
      font-size:34px;font-weight:900;letter-spacing:-3px;
      background:linear-gradient(135deg,#ffae28,#ff4f9f 36%,#7650ff 67%,#1699f4);
      box-shadow:0 22px 50px rgba(112,71,255,.38);
    }

    .progress-thin{
      height:7px;border-radius:999px;background:#edf1f7;overflow:hidden;
    }

    .progress-thin span{
      display:block;height:100%;border-radius:999px;
      background:linear-gradient(90deg,#6542fb,#168df0);
    }

    .alert{
      border-radius:16px;
      border:1px solid rgba(0,0,0,.035);
      box-shadow:0 10px 30px rgba(30,41,59,.06);
      font-size:13px;
    }

    @media (max-width:1199px){
      .content{padding:25px}
      .stat-value{font-size:24px}
    }

    @media (max-width:991px){
      .sidebar{
        transform:translateX(-100%);
        transition:transform .25s ease;
        box-shadow:20px 0 60px rgba(5,10,24,.25);
      }
      .sidebar.show{transform:translateX(0)}
      .main{margin-left:0}
      .topbar{padding:0 16px}
      .content{padding:20px 14px}
      .hero-title{font-size:24px}
      .searchbox{width:64vw}
      .login-card{grid-template-columns:1fr}
      .login-brand{display:none}
      .login-form{padding:42px 30px}
    }

    @media (max-width:575px){
      .topbar{height:68px}
      .content{padding:16px 11px}
      .panel{border-radius:20px}
      .stat-card{min-height:126px;border-radius:19px}
      .quick{min-height:100px}
      .login-page{padding:12px}
      .login-card{border-radius:24px}
      .login-form{padding:34px 22px}
    }

    .public-nav{
      width:min(1180px,calc(100% - 28px));
      margin:18px auto 0;
      display:flex;align-items:center;justify-content:space-between;gap:16px;
      background:rgba(255,255,255,.84);backdrop-filter:blur(18px);
      border:1px solid rgba(231,235,243,.92);border-radius:20px;
      padding:12px 15px;box-shadow:0 14px 38px rgba(21,31,54,.07);
      position:sticky;top:12px;z-index:50;
    }
    .public-wrap{width:min(1180px,calc(100% - 28px));margin:0 auto;padding:34px 0 60px}
    .store-hero{
      border-radius:30px;padding:48px;color:#fff;overflow:hidden;position:relative;
      background:
        radial-gradient(circle at 85% 20%,rgba(255,255,255,.19),transparent 22%),
        linear-gradient(135deg,#111c3d 0%,#5938dc 55%,#f04d9f 115%);
      box-shadow:0 26px 70px rgba(73,49,172,.20);
    }
    .store-hero h1{font-size:clamp(34px,6vw,64px);font-weight:950;letter-spacing:-2px;max-width:720px}
    .store-hero p{font-size:16px;color:rgba(255,255,255,.82);max-width:620px}
    .product-card{
      height:100%;background:#fff;border:1px solid #e9edf5;border-radius:23px;
      padding:19px;box-shadow:0 14px 38px rgba(21,31,54,.07);
      transition:transform .2s ease,box-shadow .2s ease;
    }
    .product-card:hover{transform:translateY(-5px);box-shadow:0 22px 48px rgba(21,31,54,.12)}
    .product-art{
      height:155px;border-radius:18px;display:grid;place-items:center;font-size:54px;
      background:linear-gradient(145deg,#f2efff,#edf8ff);color:#6d4aff;margin-bottom:17px;
    }
    .price{font-size:22px;font-weight:950;color:#161d31}
    .customer-hero{
      padding:28px;border-radius:25px;color:#fff;
      background:linear-gradient(135deg,#5435e9,#7d4cff 52%,#ee4c9d);
      box-shadow:0 20px 48px rgba(91,58,225,.18);
    }
    .cart-pill{background:#111a33;color:#fff;border-radius:999px;padding:9px 14px;font-weight:800;font-size:12px}


    .ym-logo-img{
      width:52px;height:52px;border-radius:15px;object-fit:cover;
      box-shadow:0 10px 26px rgba(0,0,0,.18);border:1px solid rgba(255,255,255,.16);
    }
    .login-brand-image{
      width:190px;height:190px;object-fit:cover;border-radius:28px;
      border:1px solid rgba(255,255,255,.14);
      box-shadow:0 26px 65px rgba(0,0,0,.35);
    }
    .client-luxury-hero{
      min-height:390px;border-radius:32px;padding:34px 38px;color:white;
      display:grid;grid-template-columns:1.3fr .7fr;gap:28px;align-items:center;
      overflow:hidden;position:relative;
      background:
        radial-gradient(circle at 80% 20%,rgba(255,255,255,.10),transparent 22%),
        radial-gradient(circle at 15% 90%,rgba(116,80,255,.22),transparent 28%),
        linear-gradient(135deg,#030303 0%,#0b0b0f 48%,#171522 100%);
      box-shadow:0 28px 75px rgba(7,7,15,.22);
    }
    .client-luxury-hero::after{
      content:"";position:absolute;width:390px;height:390px;border-radius:50%;
      border:1px solid rgba(255,255,255,.08);right:-170px;top:-120px;
    }
    .hero-logo-large{
      width:min(300px,100%);aspect-ratio:1/1;object-fit:cover;border-radius:28px;
      margin:auto;box-shadow:0 24px 70px rgba(0,0,0,.45);
      border:1px solid rgba(255,255,255,.13);
    }
    .luxury-kicker{
      text-transform:uppercase;letter-spacing:2.3px;font-size:10px;font-weight:850;
      color:#d9d9df;
    }
    .client-luxury-hero h1{
      font-size:clamp(36px,5vw,68px);line-height:.98;font-weight:950;letter-spacing:-2.2px;
      margin:12px 0 18px;
    }
    .client-luxury-hero p{max-width:610px;color:#c8c8d0;font-size:15px;line-height:1.7}
    .client-widget{
      background:linear-gradient(145deg,#fff,#fbfbfd);border:1px solid #e8eaf0;
      border-radius:22px;padding:19px 21px;box-shadow:0 14px 36px rgba(21,31,54,.07);
    }
    .weather-icon{
      width:45px;height:45px;border-radius:15px;display:grid;place-items:center;
      color:white;font-size:21px;background:linear-gradient(135deg,#161620,#7868ff);
    }
    .quote-card{
      background:linear-gradient(135deg,#15151a,#262331);color:#fff;
      border-radius:22px;padding:20px 22px;box-shadow:0 14px 36px rgba(18,18,25,.13);
    }
    .quote-card .quote{font-size:15px;line-height:1.55;font-weight:650}
    .catalog-img{
      width:100%;height:230px;object-fit:cover;border-radius:18px;
      background:#f3f3f6;margin-bottom:17px;
    }
    .catalog-placeholder{
      height:230px;border-radius:18px;display:grid;place-items:center;
      background:linear-gradient(145deg,#f4f4f7,#ececf2);font-size:54px;color:#6d657a;margin-bottom:17px;
    }
    .admin-product-thumb{
      width:46px;height:46px;object-fit:cover;border-radius:12px;border:1px solid #e6e8ee;
      background:#f4f5f7;
    }
    .available-dot{width:7px;height:7px;border-radius:50%;background:#1dbc7b;display:inline-block}
    .client-greeting{font-size:13px;color:#bdbdc8;margin-bottom:4px}
    @media(max-width:900px){
      .client-luxury-hero{grid-template-columns:1fr;padding:30px 24px}
      .hero-logo-large{width:220px}
    }


    .promo-badge{
      display:inline-flex;align-items:center;gap:5px;padding:7px 10px;border-radius:999px;
      background:linear-gradient(135deg,#16161c,#40365e);color:#fff;font-size:10px;font-weight:900;
      letter-spacing:.5px;text-transform:uppercase;box-shadow:0 8px 18px rgba(31,26,48,.16);
    }
    .promo-price{font-size:23px;font-weight:950;color:#d63878}
    .old-price{font-size:12px;color:#9aa1af;text-decoration:line-through;margin-left:7px}
    .promo-admin{
      border:1px solid #e7e2fa;background:linear-gradient(145deg,#fbfaff,#f7f3ff);
      border-radius:18px;padding:18px;
    }
    .edit-product-image{
      width:150px;height:150px;object-fit:cover;border-radius:20px;border:1px solid #e6e8ee;
      box-shadow:0 14px 32px rgba(21,31,54,.08);
    }

  </style>
</head>
<body>

{% if user %}
<div class="app-shell">
  <aside class="sidebar" id="sidebar">
    <div class="brand">
      <img src="{{ url_for('static', filename='ym-logo.png') }}" class="ym-logo-img" alt="YM Store">
      <div>
        <div class="brand-title">YM Store</div>
        <div class="brand-sub">Todo en un solo lugar</div>
      </div>
    </div>

    {% if user.role == 'ADMIN' %}
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
    {% else %}
    <a class="side-link {{ 'active' if active=='customer_home' else '' }}" href="{{ url_for('customer_home') }}">
      <i class="bi bi-house-heart"></i> Mi inicio
    </a>
    <a class="side-link {{ 'active' if active=='store' else '' }}" href="{{ url_for('store') }}">
      <i class="bi bi-shop"></i> Tienda
    </a>
    <a class="side-link {{ 'active' if active=='cart' else '' }}" href="{{ url_for('cart') }}">
      <i class="bi bi-cart3"></i> Mi carrito
    </a>
    <a class="side-link {{ 'active' if active=='orders' else '' }}" href="{{ url_for('customer_orders') }}">
      <i class="bi bi-bag-check"></i> Mis compras
    </a>
    <a class="side-link {{ 'active' if active=='customer_account' else '' }}" href="{{ url_for('customer_account') }}">
      <i class="bi bi-wallet2"></i> Mi cuenta y pagos
    </a>
    {% endif %}

    <div class="nav-section">Cuenta</div>
    <a class="side-link {{ 'active' if active=='account' else '' }}" href="{{ url_for('change_password') }}">
      <i class="bi bi-key"></i> Cambiar contraseña
    </a>
    <form method="post" action="{{ url_for('logout') }}" class="m-0">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <button class="side-link w-100 border-0 bg-transparent text-start" type="submit">
        <i class="bi bi-box-arrow-left"></i> Cerrar sesión
      </button>
    </form>

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
# TIENDA PÚBLICA / CLIENTES
# ============================================================

@app.route("/")
def store():
    products_list = Product.query.filter(
        Product.active.is_(True),
        Product.stock > 0
    ).order_by(Product.name).all()

    promo_map = {
        p.id: p.promotion
        for p in products_list
        if promotion_is_active(getattr(p, "promotion", None))
    }

    cart_data = session.get("cart", {})
    cart_count = sum(int(qty) for qty in cart_data.values()) if isinstance(cart_data, dict) else 0

    return page("""
    <nav class="public-nav">
      <a href="{{ url_for('store') }}" class="d-flex align-items-center gap-3">
        <img src="{{ url_for('static', filename='ym-logo.png') }}" class="ym-logo-img" alt="YM Store">
        <div>
          <div style="font-weight:950;color:#111827;letter-spacing:.2px">YM Store</div>
          <div class="section-sub">Tu estilo, aquí.</div>
        </div>
      </a>
      <div class="d-flex gap-2 align-items-center">
        <a class="cart-pill" href="{{ url_for('cart') }}"><i class="bi bi-cart3 me-1"></i> {{ cart_count }}</a>
        {% if user %}
          <a class="btn btn-gradient" href="{{ user_home_url(user) }}">Mi cuenta</a>
        {% else %}
          <a class="btn btn-light" href="{{ url_for('login') }}">Entrar</a>
          <a class="btn btn-gradient" href="{{ url_for('register') }}">Crear cuenta</a>
        {% endif %}
      </div>
    </nav>

    <div class="public-wrap">
      <section class="client-luxury-hero mb-4">
        <div style="position:relative;z-index:2">
          <div class="luxury-kicker">YM STORE • MORE THAN A STORE</div>
          <h1>Tu estilo empieza aquí.</h1>
          <p>Descubre productos seleccionados para ti. Compra desde tu cuenta, consulta tus pedidos y mantén el control de tus pagos de una forma sencilla y elegante.</p>
          <div class="d-flex gap-2 flex-wrap mt-4">
            <a href="#catalogo" class="btn btn-light px-4 py-3"><i class="bi bi-bag me-1"></i> Ver colección</a>
            {% if not user %}<a href="{{ url_for('register') }}" class="btn btn-outline-light px-4 py-3">Crear mi cuenta</a>{% endif %}
          </div>
        </div>
        <img src="{{ url_for('static', filename='ym-logo.png') }}" class="hero-logo-large" alt="Logo YM Store">
      </section>

      <div class="row g-3 mb-5">
        <div class="col-md-6">
          <div class="client-widget h-100">
            <div class="d-flex align-items-center gap-3">
              <div class="weather-icon"><i class="bi bi-cloud-sun"></i></div>
              <div>
                <div class="section-sub">El clima contigo</div>
                <div id="weatherText" style="font-weight:900;font-size:16px">Consulta el clima de tu ubicación</div>
                <div id="weatherDetail" class="section-sub">Activa ubicación para personalizar tu experiencia.</div>
              </div>
            </div>
            <button id="weatherBtn" class="btn btn-light btn-sm mt-3" type="button" onclick="loadYMWeather()">Ver mi clima</button>
          </div>
        </div>
        <div class="col-md-6">
          <div class="quote-card h-100">
            <div class="luxury-kicker mb-2">FRASE YM DE HOY</div>
            <div class="quote" id="ymQuote">“Tu estilo habla antes que tú. Elige algo que te haga sentir increíble.”</div>
          </div>
        </div>
      </div>

      <div id="catalogo" class="d-flex justify-content-between align-items-end mb-3">
        <div>
          <div class="luxury-kicker" style="color:#777">COLECCIÓN YM</div>
          <h2 class="fw-black mb-1" style="font-weight:950;font-size:30px">Productos para ti</h2>
          <div class="section-sub">Solo mostramos lo que está disponible para compra.</div>
        </div>
      </div>

      <div class="row g-4">
        {% for p in products_list %}
        <div class="col-sm-6 col-lg-4 col-xl-3">
          <div class="product-card">
            {% if p.catalog_image %}
              <img class="catalog-img" src="{{ url_for('product_image_file', product_id=p.id) }}" alt="{{ p.name }}">
            {% else %}
              <div class="catalog-placeholder"><i class="bi bi-bag-heart"></i></div>
            {% endif %}
            <div class="section-sub mb-1">{{ p.sku }}</div>
            <h3 class="h6 fw-bold mb-2" style="font-size:16px">{{ p.name }}</h3>
            <p class="text-secondary" style="font-size:12px;min-height:38px">{{ p.description or 'Una selección especial de YM Store.' }}</p>
            {% if p.id in promo_map %}
              <div class="mb-2"><span class="promo-badge"><i class="bi bi-stars"></i> {{ promo_map[p.id].label }}</span></div>
              <div class="d-flex justify-content-between align-items-end mb-3">
                <div><span class="promo-price">{{ promo_map[p.id].promo_price|money }}</span><span class="old-price">{{ p.sale_price|money }}</span></div>
                <span class="section-sub"><span class="available-dot me-1"></span> Disponible</span>
              </div>
            {% else %}
              <div class="d-flex justify-content-between align-items-center mb-3">
                <div class="price">{{ p.sale_price|money }}</div>
                <span class="section-sub"><span class="available-dot me-1"></span> Disponible</span>
              </div>
            {% endif %}
            <form method="post" action="{{ url_for('add_to_cart', product_id=p.id) }}">
              <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
              <input type="hidden" name="quantity" value="1">
              <button class="btn btn-gradient w-100 py-3"><i class="bi bi-cart-plus me-1"></i> Agregar a mi carrito</button>
            </form>
          </div>
        </div>
        {% else %}
        <div class="col-12"><div class="panel p-5 text-center text-secondary">Próximamente habrá nuevos productos disponibles.</div></div>
        {% endfor %}
      </div>
    </div>

    <script>
      const ymQuotes = [
        "El estilo verdadero no sigue tendencias: deja una impresión.",
        "Elegir bien también es una forma de cuidar cómo quieres sentirte hoy.",
        "Los mejores detalles son los que terminan formando parte de tu historia.",
        "La elegancia comienza cuando eliges con intención y lo haces tuyo.",
        "Tu estilo no necesita hablar fuerte para hacerse notar.",
        "Cada elección puede convertirse en ese detalle que transforma tu día.",
        "Lo especial no siempre es lo más grande; a veces es exactamente lo que elegiste para ti.",
        "La confianza es el mejor complemento. Todo lo demás solo la acompaña.",
        "Haz de lo cotidiano algo que se sienta exclusivamente tuyo.",
        "Un buen estilo no se trata de impresionar: se trata de representar quién eres."
      ];
      const quoteIndex = new Date().getDate() % ymQuotes.length;
      document.getElementById("ymQuote").textContent = "“" + ymQuotes[quoteIndex] + "”";

      function weatherLabel(code){
        if ([0].includes(code)) return "Despejado";
        if ([1,2,3].includes(code)) return "Parcialmente nublado";
        if ([45,48].includes(code)) return "Con neblina";
        if ([51,53,55,56,57].includes(code)) return "Llovizna";
        if ([61,63,65,66,67,80,81,82].includes(code)) return "Con lluvia";
        if ([71,73,75,77,85,86].includes(code)) return "Con nieve";
        if ([95,96,99].includes(code)) return "Tormenta";
        return "Clima actual";
      }

      function loadYMWeather(){
        const btn = document.getElementById("weatherBtn");
        const title = document.getElementById("weatherText");
        const detail = document.getElementById("weatherDetail");
        if (!navigator.geolocation){
          detail.textContent = "Tu navegador no permite consultar ubicación.";
          return;
        }
        btn.disabled = true;
        title.textContent = "Consultando tu clima...";
        navigator.geolocation.getCurrentPosition(async (pos) => {
          try{
            const lat = pos.coords.latitude;
            const lon = pos.coords.longitude;
            const endpoint = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current=temperature_2m,apparent_temperature,weather_code&temperature_unit=celsius`;
            const response = await fetch(endpoint);
            if (!response.ok) throw new Error("weather");
            const data = await response.json();
            const current = data.current;
            title.textContent = `${Math.round(current.temperature_2m)}°C · ${weatherLabel(current.weather_code)}`;
            detail.textContent = `Sensación térmica ${Math.round(current.apparent_temperature)}°C · Tu ubicación`;
            btn.textContent = "Actualizar clima";
          }catch(e){
            title.textContent = "No pudimos cargar el clima";
            detail.textContent = "Puedes seguir comprando normalmente.";
          }finally{
            btn.disabled = false;
          }
        }, () => {
          title.textContent = "Tu privacidad primero";
          detail.textContent = "No compartiste ubicación. La tienda funciona normalmente.";
          btn.disabled = false;
        }, {timeout:8000, maximumAge:600000});
      }

      window.addEventListener("DOMContentLoaded", () => {
        setTimeout(() => loadYMWeather(), 500);
      });
    </script>
    """, title="YM Store", products_list=products_list, promo_map=promo_map, cart_count=cart_count, user=current_user(), user_home_url=user_home_url)


@app.route("/registro", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def register():
    if current_user():
        return redirect(user_home_url())

    if request.method == "POST":
        try:
            name = validate_text(request.form.get("name"), "Nombre", 120, required=True)
            email = validate_text(request.form.get("email"), "Correo", 150, required=True).lower()
            phone = validate_text(request.form.get("phone"), "Teléfono", 30)
            address = validate_text(request.form.get("address"), "Dirección", 300)
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")

            if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
                raise ValueError("Ingresa un correo válido.")
            if User.query.filter(func.lower(User.username) == email).first():
                raise ValueError("Ya existe una cuenta con ese correo.")
            if len(password) < 10:
                raise ValueError("La contraseña debe tener al menos 10 caracteres.")
            if not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
                raise ValueError("La contraseña debe incluir mayúscula, minúscula y número.")
            if password != confirm:
                raise ValueError("Las contraseñas no coinciden.")

            client = Client(name=name, phone=phone, email=email, address=address)
            db.session.add(client)
            db.session.flush()

            user = User(name=name, username=email, role="CLIENTE", active=True)
            user.set_password(password)
            db.session.add(user)
            db.session.flush()

            db.session.add(CustomerProfile(user_id=user.id, client_id=client.id))
            audit("CUSTOMER_REGISTER", "CLIENT", client.id, details=email)
            db.session.commit()

            session.clear()
            session.permanent = True
            session["user_id"] = user.id
            flash("¡Tu cuenta fue creada! Bienvenido(a) a YM Store.", "success")
            return redirect(url_for("customer_home"))

        except Exception as e:
            safe_form_error(e)

    return page("""
    <div class="login-page">
      <div class="panel p-4 p-md-5" style="width:min(680px,95vw)">
        <a href="{{ url_for('store') }}" class="d-flex align-items-center gap-3 mb-4">
          <img src="{{ url_for('static', filename='ym-logo.png') }}" class="ym-logo-img" alt="YM Store">
          <div><div style="font-weight:950;font-size:22px;color:#111827">Crear cuenta</div><div class="section-sub">Cliente YM Store</div></div>
        </a>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% for category, message in messages %}<div class="alert alert-{{ 'danger' if category=='danger' else category }}">{{ message }}</div>{% endfor %}
        {% endwith %}
        <form method="post">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <div class="row g-3">
            <div class="col-md-6"><label class="form-label fw-bold">Nombre completo</label><input class="form-control" name="name" required maxlength="120"></div>
            <div class="col-md-6"><label class="form-label fw-bold">Teléfono</label><input class="form-control" name="phone" maxlength="30"></div>
            <div class="col-12"><label class="form-label fw-bold">Correo</label><input class="form-control" type="email" name="email" required maxlength="150"></div>
            <div class="col-12"><label class="form-label fw-bold">Dirección</label><input class="form-control" name="address" maxlength="300"></div>
            <div class="col-md-6"><label class="form-label fw-bold">Contraseña</label><input class="form-control" type="password" name="password" minlength="10" required></div>
            <div class="col-md-6"><label class="form-label fw-bold">Confirmar contraseña</label><input class="form-control" type="password" name="confirm_password" minlength="10" required></div>
          </div>
          <div class="section-sub mt-3">Usa mínimo 10 caracteres con mayúscula, minúscula y número.</div>
          <button class="btn btn-gradient w-100 py-3 mt-4">Crear mi cuenta</button>
        </form>
        <div class="text-center mt-4" style="font-size:12px">¿Ya tienes cuenta? <a href="{{ url_for('login') }}" style="font-weight:800;color:#7047ff">Iniciar sesión</a></div>
      </div>
    </div>
    """, title="Registro")


@app.route("/carrito/agregar/<int:product_id>", methods=["POST"])
@limiter.limit("60 per minute")
def add_to_cart(product_id):
    product = db.session.get(Product, product_id)
    if not product or not product.active or product.stock <= 0:
        flash("Este producto ya no está disponible.", "warning")
        return redirect(url_for("store"))

    try:
        qty = int(request.form.get("quantity", 1))
    except ValueError:
        qty = 1
    qty = max(1, min(qty, 20))

    cart_data = session.get("cart", {})
    if not isinstance(cart_data, dict):
        cart_data = {}
    current_qty = int(cart_data.get(str(product.id), 0))
    cart_data[str(product.id)] = min(current_qty + qty, min(product.stock, 20))
    session["cart"] = cart_data
    session.modified = True
    flash(f"{product.name} agregado al carrito.", "success")
    return redirect(request.referrer or url_for("store"))


@app.route("/carrito/quitar/<int:product_id>", methods=["POST"])
def remove_from_cart(product_id):
    cart_data = session.get("cart", {})
    if isinstance(cart_data, dict):
        cart_data.pop(str(product_id), None)
        session["cart"] = cart_data
        session.modified = True
    return redirect(url_for("cart"))


@app.route("/carrito")
def cart():
    cart_data = session.get("cart", {})
    items = []
    total = Decimal("0")
    if isinstance(cart_data, dict):
        for product_id, qty in list(cart_data.items()):
            try:
                product = db.session.get(Product, int(product_id))
                qty = max(1, int(qty))
            except (ValueError, TypeError):
                continue
            if not product or not product.active:
                continue
            qty = min(qty, product.stock)
            unit_price = effective_product_price(product)
            subtotal = unit_price * qty
            total += subtotal
            items.append((product, qty, unit_price, subtotal))

    return page("""
    {% if not user %}
    <nav class="public-nav">
      <a href="{{ url_for('store') }}" class="d-flex align-items-center gap-2"><img src="{{ url_for('static', filename='ym-logo.png') }}" class="ym-logo-img" style="width:44px;height:44px;border-radius:14px" alt="YM Store"><strong style="color:#111827">YM Store</strong></a>
      <a class="btn btn-light" href="{{ url_for('store') }}">Seguir comprando</a>
    </nav>
    <div class="public-wrap">
    {% else %}
    <div class="mb-4"><div class="hero-title">Mi carrito</div><div class="hero-sub">Revisa tu compra antes de confirmar.</div></div>
    {% endif %}

      <div class="panel p-4">
        {% for product, qty, unit_price, subtotal in items %}
          <div class="d-flex flex-wrap gap-3 align-items-center justify-content-between py-3 border-bottom">
            <div><strong>{{ product.name }}</strong><div class="section-sub">{{ qty }} × {{ unit_price|money }}</div></div>
            <div class="d-flex align-items-center gap-3"><strong>{{ subtotal|money }}</strong>
              <form method="post" action="{{ url_for('remove_from_cart', product_id=product.id) }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn btn-sm btn-light"><i class="bi bi-trash"></i></button>
              </form>
            </div>
          </div>
        {% else %}
          <div class="text-center py-5"><i class="bi bi-cart3" style="font-size:48px;color:#8f65ff"></i><h3 class="h5 fw-bold mt-3">Tu carrito está vacío</h3><a class="btn btn-gradient mt-2" href="{{ url_for('store') }}">Ver productos</a></div>
        {% endfor %}

        {% if items %}
          <div class="d-flex justify-content-between align-items-center pt-4"><div><div class="section-sub">Total</div><div class="price">{{ total|money }}</div></div>
          {% if user and user.role == 'CLIENTE' %}
            <form method="post" action="{{ url_for('checkout') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn btn-gradient py-3 px-4">Confirmar compra</button></form>
          {% elif not user %}
            <a class="btn btn-gradient py-3 px-4" href="{{ url_for('login') }}">Entrar para comprar</a>
          {% endif %}
          </div>
        {% endif %}
      </div>
    {% if not user %}</div>{% endif %}
    """, title="Carrito", active="cart", items=items, total=total, user=current_user())


@app.route("/comprar/confirmar", methods=["POST"])
@customer_required
@limiter.limit("20 per hour")
def checkout():
    profile = get_customer_profile()
    cart_data = session.get("cart", {})
    if not isinstance(cart_data, dict) or not cart_data:
        flash("Tu carrito está vacío.", "warning")
        return redirect(url_for("cart"))

    try:
        requested = []
        for pid, qty in cart_data.items():
            requested.append((int(pid), max(1, int(qty))))

        # En PostgreSQL, FOR UPDATE evita vender el mismo stock dos veces simultáneamente.
        product_ids = [pid for pid, _ in requested]
        products_locked = Product.query.filter(Product.id.in_(product_ids)).with_for_update().all()
        product_map = {p.id: p for p in products_locked}

        order_lines = []
        total = Decimal("0")
        for pid, qty in requested:
            product = product_map.get(pid)
            if not product or not product.active:
                raise ValueError("Uno de los productos ya no está disponible.")
            if qty > product.stock:
                raise ValueError(f"Stock insuficiente para {product.name}. Disponible: {product.stock}.")
            price = effective_product_price(product)
            subtotal = price * qty
            total += subtotal
            order_lines.append((product, qty, price, subtotal))

        if total <= 0:
            raise ValueError("La compra no tiene un total válido.")

        sale = Sale(client_id=profile.client_id, total=total, paid_now=0, status="PENDIENTE")
        db.session.add(sale)
        db.session.flush()

        for product, qty, price, subtotal in order_lines:
            db.session.add(SaleItem(sale_id=sale.id, product_id=product.id, quantity=qty, unit_price=price, subtotal=subtotal))
            product.stock -= qty
            add_inventory_movement(product, "VENTA_WEB", -qty, reference=f"WEB-{sale.id}")

        create_account_movement(
            profile.client_id,
            "CARGO",
            f"Compra web #{sale.id}",
            charge=total,
            reference=f"VENTA-{sale.id}"
        )
        audit("WEB_ORDER", "SALE", sale.id, details=f"total={total}")
        db.session.commit()

        session["cart"] = {}
        session.modified = True
        flash(f"¡Compra #{sale.id} confirmada! Puedes consultar tu saldo y enviar comprobante.", "success")
        return redirect(url_for("customer_orders"))

    except Exception as e:
        safe_form_error(e, "No se pudo confirmar la compra.")
        return redirect(url_for("cart"))


@app.route("/mi-cuenta")
@customer_required
def customer_home():
    profile = get_customer_profile()
    client = profile.client
    balance = client_balance(client.id)
    orders = Sale.query.filter_by(client_id=client.id).order_by(Sale.created_at.desc()).limit(5).all()
    pending_payments = Payment.query.filter_by(client_id=client.id, status="PENDIENTE").count()

    return page("""
    <div class="customer-hero mb-4" style="background:linear-gradient(135deg,#060609,#191723 62%,#513e9e)">
      <div class="d-flex flex-wrap justify-content-between align-items-center gap-4">
        <div>
          <div class="client-greeting" id="clientGreeting">Bienvenido(a) a YM Store</div>
          <h1 class="fw-bold mb-1">{{ client.name }}</h1>
          <div style="color:rgba(255,255,255,.78)">Compra, disfruta y controla tu cuenta desde un solo lugar.</div>
        </div>
        <img src="{{ url_for('static', filename='ym-logo.png') }}" class="ym-logo-img" style="width:82px;height:82px;border-radius:22px" alt="YM Store">
      </div>
    </div>

    <div class="row g-3 mb-4">
      <div class="col-lg-4"><div class="panel p-4 h-100"><div class="section-sub">Saldo pendiente</div><div class="price {{ 'debt' if balance>0 else 'credit' }}">{{ balance|money }}</div><a class="btn btn-light btn-sm mt-3" href="{{ url_for('customer_account') }}">Ver mi cuenta</a></div></div>
      <div class="col-lg-4">
        <div class="client-widget h-100">
          <div class="d-flex gap-3 align-items-center"><div class="weather-icon"><i class="bi bi-cloud-sun"></i></div><div><div class="section-sub">Clima para ti</div><div id="customerWeather" style="font-weight:900">Consulta tu clima</div><div id="customerWeatherDetail" class="section-sub">Con tu autorización.</div></div></div>
          <button class="btn btn-light btn-sm mt-3" id="customerWeatherBtn" onclick="loadCustomerWeather()">Ver clima</button>
        </div>
      </div>
      <div class="col-lg-4"><div class="quote-card h-100"><div class="luxury-kicker mb-2">UN DETALLE PARA HOY</div><div class="quote" id="customerQuote">“Disfruta lo que eliges y hazlo parte de tu estilo.”</div></div></div>
    </div>

    <div class="panel p-4 mb-4">
      <div class="d-flex flex-wrap gap-2">
        <a class="btn btn-gradient" href="{{ url_for('store') }}"><i class="bi bi-shop me-1"></i> Ir de compras</a>
        <a class="btn btn-light" href="{{ url_for('customer_orders') }}"><i class="bi bi-bag-check me-1"></i> Mis compras</a>
        {% if balance > 0 %}<a class="btn btn-light" href="{{ url_for('public_payment', token=client.payment_token) }}"><i class="bi bi-cloud-arrow-up me-1"></i> Enviar comprobante</a>{% endif %}
      </div>
    </div>

    <div class="panel p-4">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <div><h2 class="section-title">Compras recientes</h2><div class="section-sub">Tus últimos pedidos en YM Store</div></div>
        <a class="btn btn-light" href="{{ url_for('customer_orders') }}">Ver todas</a>
      </div>
      {% for order in orders %}
        <div class="d-flex justify-content-between align-items-center py-3 border-bottom">
          <div><strong>Pedido #{{ order.id }}</strong><div class="section-sub">{{ order.created_at.strftime('%d/%m/%Y %H:%M') }}</div></div>
          <div class="text-end"><strong>{{ order.total|money }}</strong><div class="section-sub">{{ order.status }}</div></div>
        </div>
      {% else %}<div class="text-center text-secondary py-4">Todavía no has realizado compras.</div>{% endfor %}
    </div>

    <script>
      const hour = new Date().getHours();
      document.getElementById("clientGreeting").textContent =
        hour < 12 ? "Buenos días ✨" : hour < 19 ? "Buenas tardes ✨" : "Buenas noches ✨";

      const customerQuotes = [
        "Tu estilo se construye con decisiones pequeñas que se sienten completamente tuyas.",
        "La confianza no se compra, pero elegir algo que amas puede recordártela.",
        "Que lo que elijas hoy tenga un lugar especial en tus próximos recuerdos.",
        "La verdadera elegancia está en sentirte cómodo con lo que representa quién eres.",
        "Tu mejor versión no necesita comparación: solo intención.",
        "Hay detalles que no cambian el mundo, pero sí pueden cambiar tu día.",
        "El estilo más memorable siempre lleva algo de tu personalidad.",
        "Disfruta elegir sin prisa; las mejores cosas se sienten correctas desde el principio."
      ];
      document.getElementById("customerQuote").textContent =
        "“" + customerQuotes[new Date().getDate() % customerQuotes.length] + "”";

      function customerWeatherLabel(code){
        if (code === 0) return "Despejado";
        if ([1,2,3].includes(code)) return "Parcialmente nublado";
        if ([45,48].includes(code)) return "Con neblina";
        if ([51,53,55,61,63,65,80,81,82].includes(code)) return "Con lluvia";
        if ([95,96,99].includes(code)) return "Tormenta";
        return "Clima actual";
      }
      function loadCustomerWeather(){
        const btn=document.getElementById("customerWeatherBtn");
        const title=document.getElementById("customerWeather");
        const detail=document.getElementById("customerWeatherDetail");
        if(!navigator.geolocation){detail.textContent="Ubicación no disponible.";return;}
        btn.disabled=true; title.textContent="Consultando...";
        navigator.geolocation.getCurrentPosition(async(pos)=>{
          try{
            const u=`https://api.open-meteo.com/v1/forecast?latitude=${pos.coords.latitude}&longitude=${pos.coords.longitude}&current=temperature_2m,apparent_temperature,weather_code&temperature_unit=celsius`;
            const r=await fetch(u); if(!r.ok) throw new Error();
            const d=await r.json(); const c=d.current;
            title.textContent=`${Math.round(c.temperature_2m)}°C · ${customerWeatherLabel(c.weather_code)}`;
            detail.textContent=`Sensación ${Math.round(c.apparent_temperature)}°C`;
            btn.textContent="Actualizar";
          }catch(e){title.textContent="Clima no disponible";detail.textContent="Inténtalo más tarde.";}
          finally{btn.disabled=false;}
        },()=>{title.textContent="Ubicación privada";detail.textContent="No compartiste tu ubicación.";btn.disabled=false;},{timeout:8000,maximumAge:600000});
      }

      window.addEventListener("DOMContentLoaded", () => {
        setTimeout(() => loadCustomerWeather(), 500);
      });
    </script>
    """, title="Mi cuenta", active="customer_home", client=client, balance=balance, orders=orders, pending_payments=pending_payments)


@app.route("/mis-compras")
@customer_required
def customer_orders():
    profile = get_customer_profile()
    orders = Sale.query.filter_by(client_id=profile.client_id).order_by(Sale.created_at.desc()).all()

    return page("""
    <div class="mb-4"><div class="hero-title">Mis compras</div><div class="hero-sub">Historial de pedidos realizados en YM Store.</div></div>
    <div class="panel p-4">
      {% for order in orders %}
        <div class="py-4 border-bottom">
          <div class="d-flex justify-content-between align-items-start gap-3 mb-3"><div><h2 class="section-title">Pedido #{{ order.id }}</h2><div class="section-sub">{{ order.created_at.strftime('%d/%m/%Y %H:%M') }}</div></div><div class="text-end"><div class="price">{{ order.total|money }}</div><span class="badge text-bg-{{ 'success' if order.status=='PAGADA' else 'warning' }}">{{ order.status }}</span></div></div>
          {% for item in order.items %}
            <div class="d-flex justify-content-between section-sub py-1"><span>{{ item.quantity }} × {{ item.product.name }}</span><span>{{ item.subtotal|money }}</span></div>
          {% endfor %}
        </div>
      {% else %}<div class="text-center py-5 text-secondary">Aún no tienes compras. <a href="{{ url_for('store') }}">Ir a la tienda</a></div>{% endfor %}
    </div>
    """, title="Mis compras", active="orders", orders=orders)


@app.route("/mi-cuenta/pagos")
@customer_required
def customer_account():
    profile = get_customer_profile()
    client = profile.client
    balance = client_balance(client.id)
    movements = AccountMovement.query.filter_by(client_id=client.id).order_by(AccountMovement.created_at.desc()).limit(100).all()
    payments = Payment.query.filter_by(client_id=client.id).order_by(Payment.created_at.desc()).all()

    return page("""
    <div class="d-flex flex-wrap justify-content-between gap-3 mb-4">
      <div><div class="hero-title">Mi cuenta y pagos</div><div class="hero-sub">Consulta cargos, abonos y comprobantes.</div></div>
      <div class="panel p-3"><div class="section-sub">Saldo pendiente</div><div class="price {{ 'debt' if balance>0 else 'credit' }}">{{ balance|money }}</div></div>
    </div>

    {% if balance > 0 %}
      <a class="btn btn-gradient mb-4" href="{{ url_for('public_payment', token=client.payment_token) }}"><i class="bi bi-cloud-arrow-up me-1"></i> Subir comprobante de pago</a>
    {% endif %}

    <div class="panel p-4 mb-4">
      <h2 class="section-title mb-3">Estado de cuenta</h2>
      <div class="table-responsive"><table class="table"><thead><tr><th>Fecha</th><th>Concepto</th><th>Cargo</th><th>Abono</th></tr></thead><tbody>
      {% for m in movements %}<tr><td>{{ m.created_at.strftime('%d/%m/%Y') }}</td><td>{{ m.concept }}</td><td class="debt">{{ m.charge|money if m.charge else '-' }}</td><td class="credit">{{ m.credit|money if m.credit else '-' }}</td></tr>
      {% else %}<tr><td colspan="4" class="text-center text-secondary">Sin movimientos.</td></tr>{% endfor %}
      </tbody></table></div>
    </div>

    <div class="panel p-4">
      <h2 class="section-title mb-3">Mis comprobantes</h2>
      <div class="table-responsive"><table class="table"><thead><tr><th>Fecha</th><th>Monto</th><th>Referencia</th><th>Estado</th></tr></thead><tbody>
      {% for p in payments %}<tr><td>{{ p.created_at.strftime('%d/%m/%Y') }}</td><td>{{ p.amount|money }}</td><td>{{ p.reference or '-' }}</td><td><span class="badge text-bg-{{ 'success' if p.status=='APROBADO' else 'warning' if p.status=='PENDIENTE' else 'danger' }}">{{ p.status }}</span></td></tr>
      {% else %}<tr><td colspan="4" class="text-center text-secondary">Sin comprobantes.</td></tr>{% endfor %}
      </tbody></table></div>
    </div>
    """, title="Mi cuenta", active="customer_account", client=client, balance=balance, movements=movements, payments=payments)


# ============================================================
# AUTH
# ============================================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user():
        return redirect(user_home_url())

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username, active=True).first()

        if user and user.check_password(password):
            session.clear()
            session.permanent = True
            session["user_id"] = user.id
            audit("LOGIN_OK", "USER", user.id)
            db.session.commit()
            flash(f"Bienvenido(a), {user.name}.", "success")
            return redirect(user_home_url(user))

        flash("Usuario o contraseña incorrectos.", "danger")

    return page("""
    <div class="login-page">
      <div class="login-card">
        <section class="login-brand">
          <div>
            <img src="{{ url_for('static', filename='ym-logo.png') }}" class="login-brand-image" alt="YM Store">
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
            <div class="badge-soft d-inline-block mb-3">Acceso a tu cuenta</div>
            <h2 class="fw-bold mb-2" style="font-size:30px">Bienvenida 👋</h2>
            <p class="text-secondary">Ingresa como cliente o administrador.</p>
          </div>

          {% with messages = get_flashed_messages(with_categories=true) %}
            {% for category, message in messages %}
              <div class="alert alert-{{ 'danger' if category=='danger' else category }}">{{ message }}</div>
            {% endfor %}
          {% endwith %}

          <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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

          <div class="text-center mt-4" style="font-size:12px">
            ¿Eres cliente nuevo? <a href="{{ url_for('register') }}" style="font-weight:800;color:#7047ff">Crear mi cuenta</a>
          </div>
          <div class="text-center text-secondary mt-3" style="font-size:11px">
            YM Store • Todo en un solo lugar
          </div>
        </section>
      </div>
    </div>
    """, title="Iniciar sesión")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("LOGOUT", "USER", session.get("user_id"))
    db.session.commit()
    session.clear()
    return redirect(url_for("login"))


@app.route("/cuenta/cambiar-password", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per hour")
def change_password():
    user = current_user()
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not user.check_password(current_password):
            flash("La contraseña actual no es correcta.", "danger")
        elif len(new_password) < 12:
            flash("La nueva contraseña debe tener al menos 12 caracteres.", "danger")
        elif new_password != confirm_password:
            flash("La confirmación no coincide.", "danger")
        elif new_password == current_password:
            flash("La nueva contraseña debe ser diferente a la actual.", "danger")
        else:
            user.set_password(new_password)
            audit("PASSWORD_CHANGE", "USER", user.id)
            db.session.commit()
            session.clear()
            flash("Contraseña actualizada. Inicia sesión nuevamente.", "success")
            return redirect(url_for("login"))

    return page("""
    <div class="mb-4">
      <div class="hero-title">Cambiar contraseña</div>
      <div class="hero-sub">Usa una contraseña única de al menos 12 caracteres.</div>
    </div>
    <div class="panel p-4" style="max-width:620px">
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label class="form-label fw-bold">Contraseña actual</label>
        <input class="form-control mb-3" type="password" name="current_password" autocomplete="current-password" required>
        <label class="form-label fw-bold">Nueva contraseña</label>
        <input class="form-control mb-3" type="password" name="new_password" autocomplete="new-password" minlength="12" required>
        <label class="form-label fw-bold">Confirmar nueva contraseña</label>
        <input class="form-control mb-4" type="password" name="confirm_password" autocomplete="new-password" minlength="12" required>
        <button class="btn btn-gradient">Actualizar contraseña</button>
      </form>
    </div>
    """, title="Cambiar contraseña", active="account")


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/admin")
@admin_required
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
@admin_required
def clients():
    if request.method == "POST":
        try:
            name = validate_text(request.form.get("name"), "Nombre", 150, required=True)
            phone = validate_text(request.form.get("phone"), "Teléfono", 30)
            email = validate_text(request.form.get("email"), "Correo", 150)
            address = validate_text(request.form.get("address"), "Dirección", 300)
            notes = validate_text(request.form.get("notes"), "Notas", 2000)

            client = Client(
                name=name,
                phone=phone,
                email=email,
                address=address,
                notes=notes
            )
            db.session.add(client)
            db.session.flush()
            audit("CLIENT_CREATE", "CLIENT", client.id)
            db.session.commit()
            flash("Cliente creado correctamente.", "success")
            return redirect(url_for("client_detail", client_id=client.id))
        except Exception as e:
            safe_form_error(e)

    q = request.args.get("q", "").strip()[:100]
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
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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
@admin_required
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

            concept = validate_text(request.form.get("concept"), "Concepto", 255)

            if action == "charge":
                create_account_movement(
                    client.id,
                    "CARGO",
                    concept or "Cargo manual",
                    charge=amount
                )
                audit("ACCOUNT_CHARGE", "CLIENT", client.id, f"amount={amount}")
                flash("Cargo agregado.", "success")

            elif action == "payment":
                balance_now = client_balance(client.id)
                if balance_now <= 0:
                    raise ValueError("El cliente no tiene deuda pendiente.")
                if amount > balance_now:
                    raise ValueError(f"El abono no puede superar el saldo pendiente ({money(balance_now)}).")
                create_account_movement(
                    client.id,
                    "ABONO",
                    concept or "Abono manual",
                    credit=amount
                )
                audit("ACCOUNT_PAYMENT", "CLIENT", client.id, f"amount={amount}")
                flash("Abono registrado.", "success")
            else:
                raise ValueError("Acción no válida.")

            db.session.commit()
        except Exception as e:
            safe_form_error(e)

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
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="hidden" name="action" value="charge">
            <input class="form-control mb-3" type="number" step="0.01" min="0.01" name="amount" placeholder="Monto" required>
            <input class="form-control mb-3" name="concept" placeholder="Concepto">
            <button class="btn btn-danger w-100">Agregar cargo</button>
          </form>
        </div>

        <div class="panel p-4">
          <h2 class="section-title mb-3 text-success"><i class="bi bi-dash-circle me-1"></i> Reducir deuda</h2>
          <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                          <button class="btn btn-sm btn-success">Aprobar</button>
                        </form>
                        <form method="post" action="{{ url_for('reject_payment', payment_id=p.id) }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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
@admin_required
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
@limiter.limit("30 per hour")
def public_payment(token):
    client = Client.query.filter_by(payment_token=token, active=True).first_or_404()

    if request.method == "POST":
        try:
            amount = Decimal(request.form.get("amount", "0"))
            balance_now = client_balance(client.id)
            if amount <= 0:
                raise ValueError("El monto debe ser mayor a cero.")
            if balance_now <= 0:
                raise ValueError("Esta cuenta no tiene saldo pendiente.")
            if amount > balance_now:
                raise ValueError(f"El monto no puede superar el saldo pendiente ({money(balance_now)}).")

            reference = validate_text(request.form.get("reference"), "Referencia", 150)
            receipt = request.files.get("receipt")
            if not receipt or not receipt.filename:
                raise ValueError("Debes adjuntar un comprobante.")
            filename = save_upload(receipt)

            payment = Payment(
                client_id=client.id,
                amount=amount,
                reference=reference,
                receipt_file=filename,
                status="PENDIENTE"
            )
            db.session.add(payment)
            db.session.commit()
            flash("Comprobante enviado. Queda pendiente de aprobación.", "success")
            return redirect(url_for("public_payment", token=token))

        except Exception as e:
            safe_form_error(e)

    balance = client_balance(client.id)

    return page("""
    <div class="login-page">
      <div class="panel p-4 p-md-5" style="width:min(610px,94vw)">
        <div class="d-flex align-items-center gap-3 mb-4">
          <img src="{{ url_for('static', filename='ym-logo.png') }}" class="ym-logo-img" alt="YM Store">
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
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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
    payment = db.session.query(Payment).filter_by(id=payment_id).with_for_update().first()
    if not payment:
        abort(404)

    if payment.status != "PENDIENTE":
        flash("Este pago ya fue procesado.", "warning")
        return redirect(url_for("client_detail", client_id=payment.client_id))

    balance_now = client_balance(payment.client_id)
    if balance_now <= 0:
        payment.status = "RECHAZADO"
        audit("PAYMENT_AUTO_REJECT", "PAYMENT", payment.id, "no outstanding balance")
        db.session.commit()
        flash("El pago fue rechazado porque la cuenta ya no tiene deuda.", "warning")
        return redirect(url_for("client_detail", client_id=payment.client_id))
    if Decimal(payment.amount) > balance_now:
        flash(f"No se aprobó: el comprobante supera el saldo actual ({money(balance_now)}).", "warning")
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
    audit("PAYMENT_APPROVE", "PAYMENT", payment.id, f"amount={payment.amount}")
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
        audit("PAYMENT_REJECT", "PAYMENT", payment.id, f"amount={payment.amount}")
        db.session.commit()

    flash("Pago rechazado.", "warning")
    return redirect(url_for("client_detail", client_id=payment.client_id))


@app.route("/uploads/<path:filename>")
@admin_required
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)



@app.route("/catalogo/imagen/<int:product_id>")
def product_image_file(product_id):
    image = ProductImage.query.filter_by(product_id=product_id).first_or_404()
    response = send_file(
        BytesIO(image.image_data),
        mimetype=image.mime_type,
        download_name=image.filename,
        max_age=86400
    )
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response


# ============================================================
# INVENTARIO
# ============================================================

@app.route("/productos", methods=["GET", "POST"])
@admin_required
def products():
    if request.method == "POST":
        try:
            sku = validate_text(request.form.get("sku"), "SKU", 60, required=True).upper()
            name = validate_text(request.form.get("name"), "Nombre", 150, required=True)
            description = validate_text(request.form.get("description"), "Descripción", 2000)

            product = Product(
                sku=sku,
                name=name,
                description=description,
                purchase_price=Decimal(request.form.get("purchase_price", "0")),
                sale_price=Decimal(request.form.get("sale_price", "0")),
                stock=int(request.form.get("stock", 0)),
                minimum_stock=int(request.form.get("minimum_stock", 0))
            )
            db.session.add(product)
            db.session.flush()

            image_payload = product_image_payload(request.files.get("product_image"))
            if image_payload:
                db.session.add(ProductImage(
                    product_id=product.id,
                    image_data=image_payload["data"],
                    mime_type=image_payload["mime_type"],
                    filename=image_payload["filename"]
                ))

            if product.stock:
                add_inventory_movement(product, "ALTA_INICIAL", product.stock, reference="ALTA")

            audit("PRODUCT_CREATE", "PRODUCT", product.id, f"stock={product.stock}")
            db.session.commit()
            flash("Producto creado.", "success")
            return redirect(url_for("products"))

        except Exception as e:
            safe_form_error(e, "No se pudo crear el producto.")

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

          <form method="post" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label class="form-label fw-bold">Foto para el catálogo</label>
            <input class="form-control mb-3" type="file" name="product_image" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp">
            <div class="section-sub mb-3">JPG, PNG o WEBP · máximo 3 MB. Esta foto sí la verá el cliente.</div>
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
              <thead><tr><th>SKU</th><th>Producto</th><th>Compra</th><th>Venta</th><th>Promo</th><th>Stock</th><th>Acciones</th></tr></thead>
              <tbody>
              {% for p in rows %}
                <tr>
                  <td><span class="badge-soft">{{ p.sku }}</span></td>
                  <td>
                    <div class="d-flex align-items-center gap-2">
                      {% if p.catalog_image %}
                        <img src="{{ url_for('product_image_file', product_id=p.id) }}" class="admin-product-thumb" alt="{{ p.name }}">
                      {% else %}
                        <div class="admin-product-thumb d-grid place-items-center"></div>
                      {% endif %}
                      <div><strong>{{ p.name }}</strong><div class="section-sub">{{ p.description or '' }}</div></div>
                    </div>
                  </td>
                  <td>{{ p.purchase_price|money }}</td>
                  <td>{{ p.sale_price|money }}</td>
                  <td>
                    {% if promotion_is_active(p.promotion) %}
                      <span class="badge text-bg-dark">{{ p.promotion.promo_price|money }}</span>
                    {% else %}<span class="section-sub">—</span>{% endif %}
                  </td>
                  <td><span class="badge rounded-pill text-bg-{{ 'danger' if p.stock <= p.minimum_stock else 'success' }}">{{ p.stock }}</span></td>
                  <td>
                    <div class="d-flex gap-1 flex-wrap">
                      <a class="btn btn-sm btn-gradient" href="{{ url_for('edit_product', product_id=p.id) }}"><i class="bi bi-pencil-square"></i> Editar</a>
                      <form class="d-flex gap-1" method="post" action="{{ url_for('adjust_stock', product_id=p.id) }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                      <input class="form-control form-control-sm" style="width:80px" type="number" name="quantity" required placeholder="+/-">
                      <button class="btn btn-sm btn-light"><i class="bi bi-check-lg"></i></button>
                      </form>
                    </div>
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
    """, title="Inventario", active="products", rows=rows, promotion_is_active=promotion_is_active)



@app.route("/productos/<int:product_id>/editar", methods=["GET", "POST"])
@admin_required
def edit_product(product_id):
    product = db.session.get(Product, product_id)
    if not product:
        abort(404)

    if request.method == "POST":
        try:
            sku = validate_text(request.form.get("sku"), "SKU", 60, required=True).upper()
            name = validate_text(request.form.get("name"), "Nombre", 150, required=True)
            description = validate_text(request.form.get("description"), "Descripción", 2000)

            duplicate = Product.query.filter(Product.sku == sku, Product.id != product.id).first()
            if duplicate:
                raise ValueError("Ya existe otro producto con ese SKU.")

            purchase_price = Decimal(request.form.get("purchase_price", "0"))
            sale_price = Decimal(request.form.get("sale_price", "0"))
            minimum_stock = int(request.form.get("minimum_stock", 0))
            if purchase_price < 0 or sale_price < 0 or minimum_stock < 0:
                raise ValueError("Precios y stock mínimo no pueden ser negativos.")

            product.sku = sku
            product.name = name
            product.description = description
            product.purchase_price = purchase_price
            product.sale_price = sale_price
            product.minimum_stock = minimum_stock
            product.active = request.form.get("active") == "on"

            image_payload = product_image_payload(request.files.get("product_image"))
            if image_payload:
                if product.catalog_image:
                    product.catalog_image.image_data = image_payload["data"]
                    product.catalog_image.mime_type = image_payload["mime_type"]
                    product.catalog_image.filename = image_payload["filename"]
                    product.catalog_image.created_at = datetime.now()
                else:
                    db.session.add(ProductImage(
                        product_id=product.id,
                        image_data=image_payload["data"],
                        mime_type=image_payload["mime_type"],
                        filename=image_payload["filename"]
                    ))

            remove_promo = request.form.get("remove_promotion") == "on"
            promo_enabled = request.form.get("promo_active") == "on"
            promo_price_raw = (request.form.get("promo_price") or "").strip()
            promo_label = validate_text(request.form.get("promo_label"), "Etiqueta de promoción", 80) or "PROMOCIÓN"
            starts_at = parse_optional_datetime(request.form.get("promo_starts_at"))
            ends_at = parse_optional_datetime(request.form.get("promo_ends_at"))

            if starts_at and ends_at and ends_at <= starts_at:
                raise ValueError("La promoción debe terminar después de su fecha de inicio.")

            if remove_promo:
                if product.promotion:
                    db.session.delete(product.promotion)
            elif promo_price_raw:
                promo_price = Decimal(promo_price_raw)
                if promo_price <= 0:
                    raise ValueError("El precio promocional debe ser mayor a cero.")
                if promo_price >= sale_price:
                    raise ValueError("El precio promocional debe ser menor que el precio normal.")

                if product.promotion:
                    promo = product.promotion
                    promo.label = promo_label
                    promo.promo_price = promo_price
                    promo.active = promo_enabled
                    promo.starts_at = starts_at
                    promo.ends_at = ends_at
                    promo.updated_at = datetime.now()
                else:
                    db.session.add(ProductPromotion(
                        product_id=product.id,
                        label=promo_label,
                        promo_price=promo_price,
                        active=promo_enabled,
                        starts_at=starts_at,
                        ends_at=ends_at
                    ))
            elif product.promotion:
                # Si existe pero dejan precio vacío, simplemente puede desactivarse.
                product.promotion.active = False

            audit("PRODUCT_EDIT", "PRODUCT", product.id, details=f"sku={product.sku}")
            db.session.commit()
            flash("Producto actualizado correctamente.", "success")
            return redirect(url_for("edit_product", product_id=product.id))

        except Exception as e:
            safe_form_error(e, "No se pudo actualizar el producto.")

    promo = product.promotion
    return page("""
    <div class="d-flex flex-wrap justify-content-between align-items-start gap-3 mb-4">
      <div>
        <div class="hero-title">Editar producto</div>
        <div class="hero-sub">Cambia información, precio, imagen o promoción sin volver a crear el producto.</div>
      </div>
      <a class="btn btn-light" href="{{ url_for('products') }}"><i class="bi bi-arrow-left me-1"></i> Inventario</a>
    </div>

    <form method="post" enctype="multipart/form-data">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <div class="row g-4">
        <div class="col-xl-7">
          <div class="panel p-4">
            <div class="d-flex flex-wrap gap-4 align-items-center mb-4">
              {% if product.catalog_image %}
                <img class="edit-product-image" src="{{ url_for('product_image_file', product_id=product.id) }}" alt="{{ product.name }}">
              {% else %}
                <div class="edit-product-image d-grid" style="place-items:center;font-size:40px;color:#777"><i class="bi bi-image"></i></div>
              {% endif %}
              <div class="flex-grow-1">
                <label class="form-label fw-bold">Cambiar foto del catálogo</label>
                <input class="form-control" type="file" name="product_image" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp">
                <div class="section-sub mt-2">Si no seleccionas otra imagen, se conserva la actual.</div>
              </div>
            </div>

            <div class="row g-3">
              <div class="col-md-5"><label class="form-label fw-bold">SKU</label><input class="form-control" name="sku" value="{{ product.sku }}" required></div>
              <div class="col-md-7"><label class="form-label fw-bold">Nombre</label><input class="form-control" name="name" value="{{ product.name }}" required></div>
              <div class="col-12"><label class="form-label fw-bold">Descripción</label><textarea class="form-control" name="description" rows="5">{{ product.description or '' }}</textarea></div>
              <div class="col-md-4"><label class="form-label fw-bold">Costo</label><input class="form-control" type="number" step="0.01" min="0" name="purchase_price" value="{{ product.purchase_price }}"></div>
              <div class="col-md-4"><label class="form-label fw-bold">Precio normal</label><input class="form-control" type="number" step="0.01" min="0" name="sale_price" value="{{ product.sale_price }}"></div>
              <div class="col-md-4"><label class="form-label fw-bold">Stock mínimo</label><input class="form-control" type="number" min="0" name="minimum_stock" value="{{ product.minimum_stock }}"></div>
              <div class="col-12">
                <div class="form-check form-switch">
                  <input class="form-check-input" type="checkbox" name="active" id="activeProduct" {% if product.active %}checked{% endif %}>
                  <label class="form-check-label fw-bold" for="activeProduct">Producto visible/activo</label>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="col-xl-5">
          <div class="promo-admin">
            <div class="d-flex align-items-center gap-3 mb-3">
              <div class="weather-icon"><i class="bi bi-stars"></i></div>
              <div><h2 class="section-title">Promoción opcional</h2><div class="section-sub">Se refleja automáticamente en tienda, carrito y compra.</div></div>
            </div>

            <label class="form-label fw-bold">Etiqueta</label>
            <input class="form-control mb-3" name="promo_label" value="{{ promo.label if promo else 'OFERTA ESPECIAL' }}" placeholder="OFERTA ESPECIAL">

            <label class="form-label fw-bold">Precio promocional</label>
            <input class="form-control mb-3" type="number" step="0.01" min="0.01" name="promo_price" value="{{ promo.promo_price if promo else '' }}" placeholder="Ej. 799.00">

            <div class="row g-3">
              <div class="col-6"><label class="form-label fw-bold">Inicia</label><input class="form-control" type="datetime-local" name="promo_starts_at" value="{{ promo.starts_at.strftime('%Y-%m-%dT%H:%M') if promo and promo.starts_at else '' }}"></div>
              <div class="col-6"><label class="form-label fw-bold">Termina</label><input class="form-control" type="datetime-local" name="promo_ends_at" value="{{ promo.ends_at.strftime('%Y-%m-%dT%H:%M') if promo and promo.ends_at else '' }}"></div>
            </div>

            <div class="form-check form-switch mt-4">
              <input class="form-check-input" type="checkbox" name="promo_active" id="promoActive" {% if promo and promo.active %}checked{% endif %}>
              <label class="form-check-label fw-bold" for="promoActive">Promoción activa</label>
            </div>

            {% if promo %}
            <div class="form-check mt-3">
              <input class="form-check-input" type="checkbox" name="remove_promotion" id="removePromo">
              <label class="form-check-label text-danger fw-bold" for="removePromo">Eliminar esta promoción</label>
            </div>
            {% endif %}
          </div>

          <div class="panel p-4 mt-4">
            <div class="section-sub">Stock actual</div>
            <div class="price">{{ product.stock }}</div>
            <div class="section-sub mt-2">El stock se cambia desde “Inventario → Ajustar” para mantener un historial correcto.</div>
          </div>
        </div>
      </div>

      <button class="btn btn-gradient py-3 px-5 mt-4"><i class="bi bi-check2-circle me-1"></i> Guardar cambios</button>
    </form>
    """, title="YM Store", active="products", product=product, promo=promo)


@app.route("/productos/<int:product_id>/ajustar", methods=["POST"])
@admin_required
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
        audit("STOCK_ADJUST", "PRODUCT", product.id, f"delta={qty}; new_stock={product.stock}")
        db.session.commit()
        flash("Stock actualizado.", "success")
    except Exception as e:
        safe_form_error(e)

    return redirect(url_for("products"))


# ============================================================
# COMPRAS
# ============================================================

@app.route("/compras", methods=["GET", "POST"])
@admin_required
def purchases():
    products_list = Product.query.filter_by(active=True).order_by(Product.name).all()

    if request.method == "POST":
        try:
            product = db.session.query(Product).filter_by(id=int(request.form["product_id"])).with_for_update().first()
            qty = int(request.form["quantity"])
            cost = Decimal(request.form["unit_cost"])
            supplier = validate_text(request.form.get("supplier"), "Proveedor", 150) or "Proveedor"

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
            audit("PURCHASE_CREATE", "PURCHASE", purchase.id, f"product={product.id}; qty={qty}; total={total}")

            db.session.commit()
            flash("Compra registrada y stock aumentado.", "success")
            return redirect(url_for("purchases"))

        except Exception as e:
            safe_form_error(e)

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
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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
@admin_required
def sales():
    clients_list = Client.query.filter_by(active=True).order_by(Client.name).all()
    products_list = Product.query.filter_by(active=True).order_by(Product.name).all()

    if request.method == "POST":
        try:
            client = db.session.get(Client, int(request.form["client_id"]))
            product = db.session.query(Product).filter_by(id=int(request.form["product_id"])).with_for_update().first()
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

            audit("SALE_CREATE", "SALE", sale.id, f"client={client.id}; product={product.id}; qty={qty}; total={total}")
            db.session.commit()
            flash("Venta registrada. Inventario y deuda actualizados.", "success")
            return redirect(url_for("sales"))

        except Exception as e:
            safe_form_error(e)

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
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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
@admin_required
def tandas():
    if request.method == "POST":
        try:
            frequency = request.form.get("frequency", "SEMANAL").upper()
            if frequency not in {"SEMANAL", "QUINCENAL", "MENSUAL"}:
                raise ValueError("Frecuencia de tanda inválida.")
            tanda = Tanda(
                name=validate_text(request.form.get("name"), "Nombre de tanda", 150, required=True),
                amount=Decimal(request.form.get("amount", "0")),
                payment_amount=Decimal(request.form.get("payment_amount", "0")),
                frequency=frequency,
                start_date=datetime.strptime(request.form.get("start_date"), "%Y-%m-%d").date()
            )
            if tanda.amount <= 0 or tanda.payment_amount <= 0:
                raise ValueError("Los montos de la tanda deben ser mayores a cero.")

            db.session.add(tanda)
            db.session.flush()
            audit("TANDA_CREATE", "TANDA", tanda.id, f"amount={tanda.amount}")
            db.session.commit()
            flash("Tanda creada.", "success")
            return redirect(url_for("tanda_detail", tanda_id=tanda.id))
        except Exception as e:
            safe_form_error(e)

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
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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
@admin_required
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

                if total_due <= 0 or turn <= 0:
                    raise ValueError("Turno y monto deben ser mayores a cero.")
                exists = TandaParticipant.query.filter_by(
                    tanda_id=tanda.id,
                    client_id=client_id
                ).first()
                if exists:
                    raise ValueError("El cliente ya participa en esta tanda.")
                if TandaParticipant.query.filter_by(tanda_id=tanda.id, turn_number=turn).first():
                    raise ValueError("Ese turno ya está ocupado en la tanda.")

                participant = TandaParticipant(
                    tanda_id=tanda.id,
                    client_id=client_id,
                    turn_number=turn,
                    total_due=total_due
                )
                db.session.add(participant)
                db.session.flush()
                create_account_movement(
                    client_id,
                    "CARGO",
                    f"Tanda {tanda.name}",
                    charge=total_due,
                    reference=f"TANDA-{tanda.id}-PART-{participant.id}"
                )
                audit("TANDA_PARTICIPANT_ADD", "TANDA_PARTICIPANT", participant.id, f"tanda={tanda.id}; client={client_id}; due={total_due}")
                db.session.commit()
                flash("Participante agregado y deuda de tanda registrada.", "success")

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
                remaining = Decimal(participant.total_due or 0) - Decimal(participant.paid or 0)
                if remaining <= 0:
                    raise ValueError("Esta participación ya está pagada.")
                if amount > remaining:
                    raise ValueError(f"El pago no puede superar el pendiente ({money(remaining)}).")

                filename = None
                receipt = request.files.get("receipt")
                if receipt and receipt.filename:
                    filename = save_upload(receipt)
                notes = validate_text(request.form.get("notes"), "Notas", 255)

                db.session.add(TandaPayment(
                    participant_id=participant.id,
                    amount=amount,
                    receipt_file=filename,
                    notes=notes
                ))

                participant.paid = Decimal(participant.paid or 0) + amount
                participant.status = "PAGADO" if participant.paid >= participant.total_due else "PENDIENTE"

                create_account_movement(
                    participant.client_id,
                    "ABONO",
                    f"Pago tanda {tanda.name}",
                    credit=amount,
                    reference=f"TANDA-{tanda.id}-PART-{participant.id}"
                )
                audit("TANDA_PAYMENT", "TANDA_PARTICIPANT", participant.id, f"amount={amount}")

                db.session.commit()
                flash("Pago de tanda registrado.", "success")

        except Exception as e:
            safe_form_error(e)

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
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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
    if User.query.filter_by(username="admin").first():
        return

    configured_password = os.getenv("ADMIN_PASSWORD")
    if IS_PRODUCTION and not configured_password:
        raise RuntimeError("ADMIN_PASSWORD es obligatoria la primera vez que se inicia producción.")

    generated_password = configured_password or secrets.token_urlsafe(18)
    if len(generated_password) < 12:
        raise RuntimeError("ADMIN_PASSWORD debe tener al menos 12 caracteres.")

    admin = User(
        name=os.getenv("ADMIN_NAME", "Yajaira Moreno"),
        username=os.getenv("ADMIN_USERNAME", "admin").strip().lower(),
        role="ADMIN"
    )
    admin.set_password(generated_password)
    db.session.add(admin)
    db.session.commit()
    print(f"Usuario inicial creado: {admin.username}")
    if not configured_password:
        print(f"Contraseña local generada (guárdala ahora): {generated_password}")
    print("Cambia la contraseña desde el panel antes de exponer datos reales.")


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
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 5000)),
        debug=(not IS_PRODUCTION and os.getenv("FLASK_DEBUG", "0") == "1")
    )