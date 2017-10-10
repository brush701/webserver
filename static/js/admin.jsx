class Admin extends React.Component {
  constructor(props) {
    super(props);
    var token = localStorage.getItem('token')
    if(token !== null) {
      this.state = {loggedIn: true,
                    token: token}
    }
    else {
      this.state = {loggedIn: false}
    }
    this.onLogin = this.onLogin.bind(this)
  }

  onLogin() {
    this.setState({loggedIn: true, token: localStorage.getItem('token')})
  }

  render() {
    if(this.state.loggedIn) {
      return (
        <SubscriberTable token={this.state.token}/>
    )
  } else {
      return (
          <Login onLogin={this.onLogin}/>
        );
    }
  }
}

class SubscriberTable extends React.Component{
  constructor(props) {
    super(props)
    var self = this
    fetch('/admin/list_subs', {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + props.token
      }
    }).then(function(response) {
        if(response.ok) {
          return response.text()
        }
        throw new Error('Network response was not ok.');
      })
      .then(function(text) {
        var subs = JSON.parse(text)
        var sublist = subs.map((sub) =>
          <tr><td>{sub.Name}</td><td>{sub.Email}</td></tr>
        )
        self.setState({subscribers: sublist})
      }).catch(function(error) {
        console.log('There has been a problem with your fetch operation: ' + error.message);
      })
  }

  render() {
    if(this.state == null) {
      return (
        <p>Error fetching subscriber list</p>
      )
    } else {
        return (
          <table className="table table-nonfluid lead" align="center">
            <thead className="thead-default"><tr><th>Name</th><th>Email</th></tr></thead>
            {this.state.subscribers}
          </table>
        );
    }
  }
}

class Login extends React.Component{
  constructor(props) {
      super(props);
      this.state = {user: '',
                    password: '',
                  };

      this.handleNameChange = this.handleNameChange.bind(this);
      this.handlePwdChange = this.handlePwdChange.bind(this);
      this.handleSubmit = this.handleSubmit.bind(this);
    }

    handleNameChange(e) {
      this.setState({user: e.target.value});
    }

    handlePwdChange(e) {
      this.setState({password: e.target.value});
    }

    handleSubmit(event) {
      event.preventDefault();
      var str = this.state.user + ":" + this.state.password
      var authStr = btoa(str)
      var props = this.props

      fetch('/login', {
        method: 'GET',
        headers: {
          'Authorization': 'Basic ' + authStr
        }
      }).then(function(response) {
          if(response.ok) {
            return response.text()
          }
          throw new Error('Network response was not ok.');
        })
        .then(function(text) {
          localStorage.setItem('token',text)
          props.onLogin()
        }).catch(function(error) {
          console.log('There has been a problem with your fetch operation: ' + error.message);
        })
    }

  render() {
    return (
      <form onSubmit={this.handleSubmit}>
        <div className="form-group">
          <label className="lead" for="name">
            User Name:
          </label>
          <input type="text" id="name" className="form-control" value={this.state.user} onChange={this.handleNameChange} />
        </div>
        <div className="form-group">
          <label className="lead" for="password">
            Password:
          </label>
          <input type="password" id="password" className="form-control" value={this.state.password} onChange={this.handlePwdChange} />
        </div>
        <div className="form-group">
          <input type="submit" className="btn btn-lg btn-default" value="Login" />
        </div>
      </form>
    );
  }
}

ReactDOM.render(
  <Admin />,
  document.getElementById('admin')
);
