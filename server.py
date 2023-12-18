from datetime import datetime, timedelta
from functools import wraps
from typing import Any
from fastapi import Depends, FastAPI, Response
from authlib.integrations.starlette_client import OAuth
from requests import get as requests_get
from starlette.middleware.sessions import SessionMiddleware
from fastapi import Request
from fastapi.responses import RedirectResponse
from pydantic_settings import BaseSettings
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy import Column, Float, Integer, String, UniqueConstraint, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel


class Env(BaseSettings):
    auth_url: str
    client_id: str
    client_secret: str
    secret_key: str
    api_key: str
    api_url: str

    class Config:
        env_file = ".env"


env = Env()  # type: ignore


app = FastAPI(
    title="Yee Social Network API",
    docs_url="/courses/2023WS-EiP/yee-social-network" if env.api_key == "" else "" + "/interactive",
    terms_of_service="https://www.youtube.com/watch?v=q6EoRBvdVPQ",
    swagger_ui_parameters={"defaultModelsExpandDepth": -1},
    openapi_tags=[
        {"name": "yeets", "description": "operations concerning yeets"},
        {"name": "users", "description": "operations concerning users"},
        {"name": "likes", "description": "operations concerning likes"},
        {"name": "follows", "description": "operations concerning follows"},
    ],
)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SessionMiddleware, secret_key=env.secret_key, max_age=94608000)


laurel = OAuth()
laurel.register(
    "laurel",
    server_metadata_url=env.auth_url + "/.well-known/openid-configuration",
    client_id=env.client_id,
    client_secret=env.client_secret,
    client_kwargs={"scope": "openid profile email"},
)

engine = create_engine(
    "sqlite:///database.db", connect_args={"check_same_thread": False}
)
session = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class Yeets(Base):
    __tablename__ = "yeets"

    id = Column(Integer, unique=True, primary_key=True)
    date = Column(Float)
    author = Column(String)
    content = Column(String)


class Follows(Base):
    __tablename__ = "follows"

    id = Column(Integer, unique=True, primary_key=True)
    user = Column(String)
    follower = Column(String)

    __table_args__ = (UniqueConstraint("user", "follower", name="_user_following_uc"),)


class Likes(Base):
    __tablename__ = "likes"

    id = Column(Integer, unique=True, primary_key=True)
    user = Column(String)
    yeet = Column(Integer)

    __table_args__ = (UniqueConstraint("user", "yeet", name="_user_yeet_uc"),)


Base.metadata.create_all(bind=engine)


def database():
    db = session()
    try:
        yield db
    finally:
        db.close()


USERS = [
    "mw1187",
    "mw650",
    "hs1087",
    "thiemann",
    "lk473",
    "th344",
    "th236",
    "ts593",
    "sd318",
    "cu35",
    "dm296",
    "vb170",
    "kk179",
    "th322",
    "sk925",
    "tb305",
    "me351",
    "ms2262",
    "np163",
    "jp373",
    "az174",
    "gd38",
]


def ttl_cache(f, ttl=timedelta(minutes=20)):
    time, value = None, None

    @wraps(f)
    def wrapped(*args, **kwargs):
        nonlocal time
        nonlocal value
        now = datetime.now()
        if not time or now - time > ttl:
            value = f(*args, **kwargs)
            time = now
        return value

    return wrapped


@ttl_cache
def is_valid_user(username: str) -> bool:
    if username in USERS:
        return True
    if env.api_url == "":
        return True
    response = requests_get(
        f"{env.api_url}/course/2023WS-EiP/is_student/{username}",
        headers={"Authorization": env.api_key},
    )
    return response.status_code == 200


@ttl_cache
def get_all_users() -> list[str]:
    if env.api_url == "":
        return USERS
    response = requests_get(
        f"{env.api_url}/course/2023WS-EiP/students",
        headers={"Authorization": env.api_key},
    )
    return list(response.json().keys()) + USERS


def authorized(f):
    @wraps(f)
    async def decorated(*args, **kwargs):
        request = kwargs["request"]
        if not request.session.get("user"):
            request.session["redirect"] = str(request.url)
            return RedirectResponse(
                env.auth_url
                + "/auth/login?redirect="
                + "/courses/2023WS-EiP/yee-social-network"
                if env.api_key == ""
                else "" + str(request.url_for("login")),
            )
        return await f(*args, **kwargs)

    return decorated


@app.get("/", include_in_schema=False)
@authorized
async def root(request: Request) -> RedirectResponse:
    return RedirectResponse("/courses/2023WS-EiP/yee-social-network" if env.api_key == "" else "" + "/interactive")


@app.get("/login", include_in_schema=False)
@limiter.limit("20/minute")
async def login(request: Request) -> dict[str, Any]:
    client = laurel.create_client("laurel")
    return await client.authorize_redirect(  # type: ignore
        request, "/courses/2023WS-EiP/yee-social-network" if env.api_key == "" else "" + request.url_for("callback")
    )


@app.get("/callback", include_in_schema=False, response_model=None)
@limiter.limit("20/minute")
async def callback(request: Request) -> dict[str, Any] | RedirectResponse:
    client = laurel.create_client("laurel")
    token = await client.authorize_access_token(request)  # type: ignore
    request.session["user"] = token["userinfo"]
    if request.session.get("redirect"):
        url = request.session.pop("redirect")
        return RedirectResponse(url)
    return {"username": token["userinfo"]["sub"]}


async def error(response: Response, message: str) -> dict[str, Any]:
    response.status_code = 400
    return {"message": message}


@app.get(
    "/yeets/all/{amount}",
    tags=["yeets"],
    summary="get the latest yeets from the overall network",
    description="get the last `amount` (where `amount` must be a strictly positive integer) yeets on the network as list of dictionaries of the form {yeet_id: int, author: str, content: str, date: int, likes: int}",
)
@limiter.limit("20/minute")
@authorized
async def all_yeets(
    request: Request,
    amount: int,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    if amount <= 0:
        return await error(
            response,
            f"integer {amount} is not a strictly positive number for the amount of yeets to fetch!",
        )

    return {
        "response": [
            {
                "yeet_id": yeet.id,
                "author": yeet.author,
                "content": yeet.content,
                "date": yeet.date,
            }
            for yeet in reversed(
                database.query(Yeets).order_by(Yeets.id.desc()).limit(amount).all()
            )
        ]
    }


@app.get(
    "/yeets/{yeet_id}/likes",
    tags=["yeets"],
    summary="get all users who liked a yeet",
    description="get a list of strings of all users who liked the yeet with yeet_id `yeet`",
)
@limiter.limit("20/minute")
@authorized
async def yeet_likes(
    request: Request,
    yeet_id: int,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    if not database.query(
        database.query(Yeets).filter_by(id=yeet_id).exists()
    ).scalar():
        return await error(
            response, f"there does not exist a yeet with yeet_id {yeet_id}"
        )

    return {
        "response": [
            like.user
            for like in database.query(Likes)
            .filter_by(yeet=yeet_id)
            .order_by(Likes.id.desc())
            .all()
        ]
    }


class Content(BaseModel):
    content: str


class YeetId(BaseModel):
    id: int


@app.post(
    "/yeets/add",
    tags=["yeets"],
    summary="create an new yeet",
    description="creates an new yeet, where the request body dictionary must be of the form {content: str}",
)
@limiter.limit("20/minute")
@authorized
async def add_yeet(
    request: Request,
    content: Content,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    if len(content.content) > 420:
        return await error(
            response,
            "maximum content length of a yeet is 420 characters (including spaces)!",
        )
    database.add(
        Yeets(
            date=datetime.utcnow(),
            author=request.session["user"]["sub"],
            content=content.content,
        )
    )
    database.commit()
    return {}


@app.post(
    "/yeets/remove",
    tags=["yeets"],
    summary="remove a yeet",
    description="remove a yeet, where the request body dictionary must be of the form {yeet_id: int}",
)
@limiter.limit("20/minute")
@authorized
async def remove_yeet(
    request: Request,
    yeet_id: YeetId,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    first = (
        database.query(Yeets)
        .filter_by(id=yeet_id.id, author=request.session["user"]["sub"])
        .first()
    )
    if not first:
        return await error(
            response,
            f"there does not exist a yeet with yeet_id {yeet_id} yeeted by you!",
        )
    database.delete(first)
    database.commit()
    return {}


@app.post(
    "/likes/add",
    tags=["likes"],
    summary="like a yeet",
    description="like a yeet by using its yeet_id, where the request body dictionary must be of the form {yeet_id: int}",
)
@limiter.limit("20/minute")
@authorized
async def add_like(
    request: Request,
    yeet_id: YeetId,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    if not database.query(
        database.query(Yeets).filter_by(id=yeet_id.id).exists()
    ).scalar():
        return await error(response, f"there does not exist a yeet with id {yeet_id}!")
    if database.query(
        database.query(Likes)
        .filter_by(yeet=yeet_id.id, user=request.session["user"]["sub"])
        .exists()
    ).scalar():
        return await error(
            response, f"your already liked the yeet with id {yeet_id.id}!"
        )
    database.add(Likes(yeet=yeet_id.id, user=request.session["user"]["sub"]))
    database.commit()
    return {}


@app.post(
    "/likes/remove",
    tags=["likes"],
    summary="un-like a yeet",
    description="un-like a yeet by using its yeet_id, where the request body dictionary must be of the form {yeet_id: int}",
)
@limiter.limit("20/minute")
@authorized
async def remove_like(
    request: Request,
    yeet_id: YeetId,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    if not database.query(
        database.query(Yeets).filter_by(id=yeet_id.id).exists()
    ).scalar():
        return await error(
            response, f"there does not exist a yeet with yeet_id {yeet_id}!"
        )
    first = (
        database.query(Likes)
        .filter_by(yeet=yeet_id.id, user=request.session["user"]["sub"])
        .first()
    )
    if not first:
        return await error(
            response, f"you have not yet liked yeet with yeet_id {yeet_id}!"
        )
    database.delete(first)
    database.commit()
    return {}


@app.get(
    "/users/all",
    tags=["users"],
    summary="get all users registered on the network",
    description="get a list of strings of all users who are registered on the network",
)
@limiter.limit(
    "20/minute",
)
@authorized
async def all_users(
    request: Request,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    return {
        "response": [
            {
                "username": user,
            }
            for user in get_all_users()
        ]
    }


@app.get(
    "/users/{user}/yeets",
    tags=["users"],
    summary="get all yeets yeeted by an user",
    description="get all yeets of user `user` as list of dictionaries of the form {yeet_id: int, author: str, content: str, date: int, likes: int}",
)
@limiter.limit("20/minute")
@authorized
async def yeets(
    request: Request,
    user: str,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    if not is_valid_user(user):
        return await error(response, f"user {user} does not exist!")

    return {
        "response": [
            {
                "yeet_id": yeet.id,
                "author": yeet.author,
                "content": yeet.content,
                "date": yeet.date,
            }
            for yeet in reversed(
                database.query(Yeets)
                .filter_by(author=user)
                .order_by(Yeets.id.desc())
                .all()
            )
        ]
    }


@app.get(
    "/users/{user}/following",
    tags=["users"],
    summary="get all users who an user follows",
    description="get a list of strings of all users who `user` follows",
)
@limiter.limit("20/minute")
@authorized
async def following(
    request: Request,
    user: str,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    if not is_valid_user(user):
        return await error(response, f"user {user} does not exist!")
    return {
        "response": [
            following.user
            for following in database.query(Follows).filter_by(follower=user).all()
        ]
    }


@app.get(
    "/users/{user}/followers",
    tags=["users"],
    summary="get all users who follow an user",
    description="get a list of strings of all users who follow `user`",
)
@limiter.limit("20/minute")
@authorized
async def followers(
    request: Request,
    user: str,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    if not is_valid_user(user):
        return await error(response, f"user {user} does not exist!")
    return {
        "response": [
            following.follower
            for following in database.query(Follows).filter_by(user=user).all()
        ]
    }


@app.get(
    "/users/{user}/likes",
    tags=["users"],
    summary="get all yeets who an user liked",
    description="get a list of integers of all yeet ids who `user` liked",
)
@limiter.limit("20/minute")
@authorized
async def user_likes(
    request: Request,
    user: str,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    if not is_valid_user(user):
        return await error(response, f"user {user} does not exist!")
    return {
        "response": [
            like.yeet for like in database.query(Likes).filter_by(user=user).all()
        ]
    }


class User(BaseModel):
    username: str


@app.post(
    "/follows/add",
    tags=["follows"],
    summary="follow a user",
    description="follow a user by its username, where the request body dictionary must be of the form {username: str}",
)
@limiter.limit("20/minute")
@authorized
async def follow(
    request: Request,
    user: User,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    if not is_valid_user(user.username):
        return await error(response, f"user {user.username} does not exist!")
    if user.username == request.session["user"]["sub"]:
        return await error(response, "what did you expect by following yourself?!")
    if database.query(
        database.query(Follows)
        .filter_by(follower=request.session["user"]["sub"], user=user.username)
        .exists()
    ).scalar():
        return await error(response, f"you already follow {user.username}!")
    database.add(Follows(user=user.username, follower=request.session["user"]["sub"]))
    database.commit()
    return {}


@app.post(
    "/follows/remove",
    tags=["follows"],
    summary="un-follow a user",
    description="un-follow a user by its username, where the request body dictionary must be of the form {username: str}",
)
@limiter.limit("20/minute")
@authorized
async def unfollow(
    request: Request,
    user: User,
    response: Response,
    database: Session = Depends(database),
) -> dict[str, Any]:
    if not is_valid_user(user.username):
        return await error(response, f"user {user.username} does not exist!")
    first = (
        database.query(Follows)
        .filter_by(follower=request.session["user"]["sub"], user=user.username)
        .first()
    )
    if not first:
        return await error(response, f"you do not yet follow {user.username}!")
    database.delete(first)
    database.commit()
    return {}
