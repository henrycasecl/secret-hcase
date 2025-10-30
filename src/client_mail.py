import os
import sys
import getpass
import mimetypes
from pathlib import Path
import smtplib
from email.message import EmailMessage
from typing import Optional, List

# -----------------------
# Configurables / Inputs
# -----------------------
# Puedes dejar vacíos para que el script pregunte en tiempo de ejecución.
EMAIL_USER = "fadmin@banco.com"  # IGNORE
EMAIL_PASS = "123momia2025"      # IGNORE

# SMTP server config (puedes cambiar)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")  # cambiar si no usas Gmail
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))        # 587 para STARTTLS, 465 para SSL
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "0") == "1"  # si True usa SMTP_SSL con puerto 465

# -----------------------
# Funciones utilitarias
# -----------------------
def ask_credentials():
    global EMAIL_USER, EMAIL_PASS
    if not EMAIL_USER:
        EMAIL_USER = input("Correo (remitente) > ").strip()
    if not EMAIL_PASS:
        EMAIL_PASS = getpass.getpass("Contraseña / App password (no se mostrará) > ").strip()

def build_message(
    *,
    subject: str,
    sender: str,
    recipients: List[str],
    body_text: Optional[str] = None,
    body_html: Optional[str] = None,
    attachments: Optional[List[Path]] = None
) -> EmailMessage:
    """
    Construye EmailMessage que puede contener texto, html y adjuntos.
    """
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject

    # Añadir cuerpo: si hay HTML lo ponemos como alternativa
    if body_html and body_text:
        msg.set_content(body_text)
        msg.add_alternative(body_html, subtype="html")
    elif body_html:
        # Si solo HTML, añadir una versión mínima en texto
        msg.set_content("Este correo contiene HTML. Habilita un cliente con HTML para verlo.")
        msg.add_alternative(body_html, subtype="html")
    else:
        msg.set_content(body_text or "")

    # Adjuntos (si los hay)
    if attachments:
        for p in attachments:
            p = Path(p)
            if not p.exists() or not p.is_file():
                print(f"[WARN] adjunto no existe: {p}", file=sys.stderr)
                continue
            ctype, encoding = mimetypes.guess_type(str(p))
            if ctype is None:
                maintype, subtype = "application", "octet-stream"
            else:
                maintype, subtype = ctype.split("/", 1)
            with p.open("rb") as f:
                data = f.read()
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=p.name)
    return msg

def send_email(msg: EmailMessage, smtp_host: str, smtp_port: int, user: str, password: str, use_ssl: bool = False):
    """
    Envía el EmailMessage usando SMTP. Soporta STARTTLS (por defecto) y SSL.
    """
    recipients = msg.get_all("To", [])
    if use_ssl:
        server = smtplib.SMTP_SSL(host=smtp_host, port=smtp_port, timeout=15)
        try:
            server.login(user, password)
            server.send_message(msg, from_addr=user, to_addrs=recipients)
        finally:
            server.quit()
    else:
        server = smtplib.SMTP(host=smtp_host, port=smtp_port, timeout=15)
        try:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(user, password)
            server.send_message(msg, from_addr=user, to_addrs=recipients)
        finally:
            server.quit()

# -----------------------
# Ejecución principal (demo)
# -----------------------
def main():
    ask_credentials()

    # Ejemplo de destinatarios; puedes modificarlos
    to_list = input("Destinatario(s) (separados por comas) > ").strip().split(",")
    to_list = [t.strip() for t in to_list if t.strip()]
    if not to_list:
        print("No se especificaron destinatarios. Abortando.")
        return

    # Construir mensaje de ejemplo (texto + HTML + adjunto opcional)
    subject = "Prueba de envío desde send_email.py"
    body_text = (
        "Hola,\n\n"
        "Este es un correo de prueba enviado por un script de ejemplo.\n"
        "Saludos.\n"
    )
    body_html = """\
    <html>
      <body>
        <p>Hola,<br><br>
           <b>Este es un correo de prueba</b> enviado por un <i>script</i> de ejemplo.<br>
           Saludos.
        </p>
      </body>
    </html>
    """

    # Preguntar si desean adjuntar un archivo
    attach_input = input("Ruta a archivo a adjuntar (dejar vacío si no aplica) > ").strip()
    attachments = [Path(attach_input)] if attach_input else None

    msg = build_message(
        subject=subject,
        sender=EMAIL_USER,
        recipients=to_list,
        body_text=body_text,
        body_html=body_html,
        attachments=attachments
    )

    print("\nEnviando correo...")
    try:
        send_email(msg, smtp_host=SMTP_HOST, smtp_port=SMTP_PORT, user=EMAIL_USER, password=EMAIL_PASS, use_ssl=SMTP_USE_SSL)
        print("Correo enviado correctamente ✅")
    except smtplib.SMTPAuthenticationError:
        print("Error: autenticación fallida. Revisa correo/contraseña o usa una 'app password' si el proveedor lo requiere.")
    except Exception as e:
        print(f"Error al enviar: {e}")

if __name__ == "__main__":
    main()