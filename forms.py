from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email, length
from flask_ckeditor import CKEditorField
import email_validator


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class CreateUserForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email("Please enter a valid email address")])
    password = PasswordField("Password", validators=[DataRequired(),
                                                     length(min=6, message="Length should be at least 6")])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Create User")


class LoginUserForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email("Please enter a valid email address")])
    password = PasswordField("Password", validators=[DataRequired(),
                                                     length(min=6, message="Length should be at least 6")])
    submit = SubmitField("Login")


class CommentForm(FlaskForm):
    body = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Add comment")
