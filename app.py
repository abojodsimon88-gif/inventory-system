import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

import pymysql
from pymysql.cursors import DictCursor
from flask import (
    Flask, render_template_string, request, redirect, url_for, session, abort, Response,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from zoneinfo import ZoneInfo
    LOCAL_TZ = ZoneInfo('Asia/Jerusalem')
except Exception:   # لو لم تتوفر قاعدة المناطق الزمنية
    LOCAL_TZ = timezone(timedelta(hours=2))

# ----------------------------------------------------------------------
# الإعدادات
# ----------------------------------------------------------------------