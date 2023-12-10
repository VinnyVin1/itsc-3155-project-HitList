from model import db, Posts

class post_repository():

    def get_all_posts(self):
        return Posts.query.all()