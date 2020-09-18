"""add node_name field to results

Revision ID: 8e443fbb475a
Revises: 2a5b0607d2bd
Create Date: 2020-09-18 14:29:34.841271

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8e443fbb475a'
down_revision = '2a5b0607d2bd'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('result', sa.Column('node_name', sa.String(length=256), nullable=True))
    op.add_column('validation_result', sa.Column('node_name', sa.String(length=256), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('validation_result', 'node_name')
    op.drop_column('result', 'node_name')
    # ### end Alembic commands ###