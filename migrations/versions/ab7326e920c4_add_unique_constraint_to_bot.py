"""Add unique constraint to bot

Revision ID: ab7326e920c4
Revises: 8f465cbfa295
Create Date: 2024-09-24 10:57:02.070266

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ab7326e920c4'
down_revision = '8f465cbfa295'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('bot', schema=None) as batch_op:
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.alter_column('client_id',
               existing_type=sa.TEXT(),
               type_=sa.String(length=255),
               nullable=False)
        batch_op.alter_column('secret_key',
               existing_type=sa.TEXT(),
               type_=sa.String(length=255),
               nullable=False)
        batch_op.alter_column('start_hour',
               existing_type=sa.TEXT(),
               type_=sa.String(length=5),
               existing_nullable=False,
               existing_server_default=sa.text("'00:00'"))
        batch_op.alter_column('end_hour',
               existing_type=sa.TEXT(),
               type_=sa.String(length=5),
               existing_nullable=False,
               existing_server_default=sa.text("'23:59'"))
        batch_op.create_unique_constraint('uq_user_name', ['user_id', 'name'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('bot', schema=None) as batch_op:
        batch_op.drop_constraint('uq_user_name', type_='unique')
        batch_op.alter_column('end_hour',
               existing_type=sa.String(length=5),
               type_=sa.TEXT(),
               existing_nullable=False,
               existing_server_default=sa.text("'23:59'"))
        batch_op.alter_column('start_hour',
               existing_type=sa.String(length=5),
               type_=sa.TEXT(),
               existing_nullable=False,
               existing_server_default=sa.text("'00:00'"))
        batch_op.alter_column('secret_key',
               existing_type=sa.String(length=255),
               type_=sa.TEXT(),
               nullable=True)
        batch_op.alter_column('client_id',
               existing_type=sa.String(length=255),
               type_=sa.TEXT(),
               nullable=True)
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=True)

    # ### end Alembic commands ###
