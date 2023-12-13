from src.models import db, User, Posts
import datetime

def test_user():
    user = User(
        display_name='Johnny S',
        username='user1a',
        password='passwordABC123',
        first_name='John',
        last_name='Smith',
        email='jsmith123@gmail.com'
    )
    db.session.add(user)
    db.session.commit()

    retrieved_user = User.query.filter_by(username='user1a').first()
    assert retrieved_user is not None
    assert retrieved_user.email == 'jsmith123@gmail.com'

def test_posts():
    created_time = datetime.datetime.now()
    post = Posts(
        user_name='user1a',
        created=created_time,
        title='Test Post',
        content='This is a test. ABC_123!'
    )
    db.session.add(post)
    db.session.commit()

    retrieved_post = Posts.query.filter_by(title='Test Post').first()
    assert retrieved_post is not None
    assert retrieved_post.content == 'This is a test. ABC_123!'