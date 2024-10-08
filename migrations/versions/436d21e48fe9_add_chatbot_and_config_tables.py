"""Add Chatbot and Config tables

Revision ID: 436d21e48fe9
Revises: ab7326e920c4
Create Date: 2024-09-24 17:36:55.068336

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision = '436d21e48fe9'
down_revision = 'ab7326e920c4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('bot')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('bot',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('user_id', sa.INTEGER(), nullable=False),
    sa.Column('name', sa.VARCHAR(length=255), nullable=False),
    sa.Column('settings', sqlite.JSON(), nullable=True),
    sa.Column('created_at', sa.DATETIME(), nullable=True),
    sa.Column('updated_at', sa.DATETIME(), nullable=True),
    sa.Column('client_id', sa.VARCHAR(length=255), nullable=False),
    sa.Column('secret_key', sa.VARCHAR(length=255), nullable=False),
    sa.Column('start_hour', sa.VARCHAR(length=5), server_default=sa.text("'00:00'"), nullable=False),
    sa.Column('end_hour', sa.VARCHAR(length=5), server_default=sa.text("'23:59'"), nullable=False),
    sa.Column('retry_time_between_calls', sa.INTEGER(), server_default=sa.text('0'), nullable=False),
    sa.Column('max_retries', sa.INTEGER(), server_default=sa.text('1'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'name', name='uq_user_name')
    )
    # ### end Alembic commands ###
