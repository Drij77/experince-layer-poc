#!/bin/bash
set -e

echo "Waiting for PostgreSQL to be ready..."
until pg_isready -h postgres -U auth_user -d auth_db; do
  echo "Waiting for database..."
  sleep 2
done

echo "PostgreSQL is ready!"

echo "Running database schema initialization..."
PGPASSWORD=auth_password_change_in_production psql -h postgres -U auth_user -d auth_db -f /app/schema_postgres.sql

echo "Database initialized successfully!"
