
from flask import Flask,jsonify
from flask import request
from flask.helpers import make_response
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
import datetime
from functools import wraps

app=Flask(__name__)
api=Api(app)
CORS(app)
cors = CORS(app, 
resources={r"/api/*": 
{
    "origins": "*"
    }
})
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://ejeawndpkhpnbm:22cd5a9e603cb2f24f32322af74d5eb62a28b456485f93ab06505a4a964d0ecf@ec2-52-21-153-207.compute-1.amazonaws.com:5432/d4j03uo92120ms'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['SECRET_KEY']="thisissercretkey"
db = SQLAlchemy(app)

class User(db.Model):
    ID=db.Column(db.Integer, primary_key=True)
    Public_ID=db.Column(db.String(200), unique=True)
    Employee_ID=db.Column(db.String(200),unique=True)
    Name=db.Column(db.String(200))
    Password=db.Column(db.String(200))
    Address=db.Column(db.String(300))
    Mobile=db.Column(db.String(200))
    Is_Admin=db.Column(db.Boolean)

class SlotBooking(db.Model):
    ID=db.Column(db.Integer, primary_key=True)
    Date=db.Column(db.String(200))
    Time=db.Column(db.String(200))
    Available=db.Column(db.Boolean)
    Employee_ID_Registered=db.Column(db.String(200))


@app.route('/api/user', methods=['POST'])
def create_users():
    if request.method=='POST':
        data=request.get_json()
        hashed_password=generate_password_hash(data['Password'],method='sha256')
        try:
            new_user=User(Public_ID=str(uuid.uuid4()),Employee_ID=data['Employee_ID'],Name=data['Name'],Password=hashed_password,Address=data['Address'],Mobile=data['Mobile'],Is_Admin=data['Is_Admin'])
            db.session.add(new_user)
            db.session.commit()
        except:
            return jsonify({'Message':'Couldnt Create'}),400
        return ('Created')

@app.route('/api/login')
def login():
    auth=request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify',401)
    
    user=User.query.filter_by(Employee_ID=auth.username).first()
    if not user:
        return make_response('Could not verify',401)
    
    if check_password_hash(user.Password,auth.password):
        token=jwt.encode({'Public_ID':user.Public_ID,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=1000)},app.config['SECRET_KEY'])
        return jsonify({"Token": token})
    return make_response('Could not verify',401)


def token_required(f): 
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']
        if not token:
            return jsonify({'Message':'Token is missing!'}),401
        Users=User.query.all()
        Data1=[]
        CurrentUser=None
        for User1 in Users:
            UserData= {}
            UserData['Public_ID']=User1.Public_ID
            UserData["Employee_ID"]=User1.Employee_ID
            UserData['Is_Admin']=User1.Is_Admin
            Data1.append(UserData)
        try:
            data=jwt.decode(token,app.config['SECRET_KEY'],algorithms="HS256")
            CurrentUser=User.query.filter_by(Public_ID=data['Public_ID']).first()
             
        except:
            return jsonify({'message':'Token is invalid'}),401

        return f(CurrentUser,*args,**kwargs)

    return decorated


@app.route('/api/user', methods=['GET'])
@token_required
def get_all_users(CurrentUser):
    User1=User.query.filter_by(Public_ID=CurrentUser.Public_ID).first()
    if not User1:
        return jsonify({'Message':'No user Data'})
    UserData= {}
    UserData['Public_ID']=User1.Public_ID
    UserData["Name"]=User1.Name
    UserData["Employee_ID"]=User1.Employee_ID
    UserData['Is_Admin']=User1.Is_Admin
    
    return jsonify({"Users":UserData})

@app.route('/api/createslot',methods=['POST'])
@token_required
def create_all_slot(CurrentUser):

    if request.method=='POST':
     if(CurrentUser.Is_Admin):
         data=request.get_json()
         Isexist=SlotBooking.query.filter_by(Date=data['Date'], Time=data['Time']).first()
         if Isexist:
             return ("Duplicate exist"),404
         try:
             new_slot=SlotBooking(Date=data['Date'],Time=data['Time'],Available=True,Employee_ID_Registered='xx')
             db.session.add(new_slot)
             db.session.commit()
             return jsonify({"Message":"Added success"}) ,200
         except:
            return("Invalid Data")
    else:
        return("Illegal Access")

@app.route('/api/createslot',methods=['GET'])
def get_all_slots():
    if request.method=='GET':
        slots=SlotBooking.query.all()
        Data=[]
        for slot in slots:
            UserData={}
            UserData['Date']=slot.Date
            UserData['Time']=slot.Time
            UserData['Available']=slot.Available
            UserData['Employee_ID_Registered']=slot.Employee_ID_Registered
            UserData['ID']=slot.ID
            Data.append(UserData)
        return jsonify(Data)


@app.route('/api/createslot/<int:ID>',methods=['PUT'])
@token_required
def put(self,ID):
    if request.method=='PUT':
        todo = SlotBooking.query.filter_by(ID=ID).first()
        if not todo:
            return{"MessTime":"Data Doesnt exist"} ,401
        
        if(todo.Available==False or todo.Available=="false"):
            return({"Message":"Slot not available"}),400
        else:
            todo.Available=False
            todo.Employee_ID_Registered=self.Employee_ID
            db.session.commit()
            return{"Message":"Updated Successfully"},200