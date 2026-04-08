#!/usr/bin/env python3
from rucio.db.sqla.util import build_database, create_base_vo, create_root_account
from sqlalchemy.exc import IntegrityError

build_database()

try:
    create_base_vo()
except IntegrityError:
    print("Base VO already exists — skipping.")

try:
    create_root_account()
except IntegrityError:
    print("Root account already exists — skipping.")

print("DB bootstrap complete.")
