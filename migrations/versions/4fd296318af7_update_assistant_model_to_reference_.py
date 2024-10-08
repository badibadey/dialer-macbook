"""Update Assistant model to reference users table

Revision ID: 4fd296318af7
Revises: 436d21e48fe9
Create Date: 2024-09-24 18:04:19.050583

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4fd296318af7'
down_revision = '436d21e48fe9'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('assistant',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('language_model', sa.String(length=100), nullable=False),
    sa.Column('prompt', sa.Text(), nullable=False),
    sa.Column('welcome_message', sa.String(length=255), nullable=False),
    sa.Column('actions', sa.Text(), nullable=False),
    sa.Column('avatar', sa.String(length=255), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('assistant')
    # ### end Alembic commands ###
