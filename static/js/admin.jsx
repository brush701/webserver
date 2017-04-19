class Admin extends React.Component {
  constructor(props) {
    super(props);
    var token = localStorage.getItem('token')
    if(token !== null) {
      this.state = {loggedIn: true}
    }
    else {
      this.state = {loggedIn: false}
    }
    this.onLogin = this.onLogin.bind(this)
  }

  onLogin() {
    this.setState({loggedIn: true})
  }

  render() {
    if(this.state.loggedIn) {
      return (
      <p>
        Success
      </p>
    )
  } else {
      return (
          <Login onLogin={this.onLogin}/>
        );
    }
  }
}

class DbElement extends React.Component{
  constructor(props) {
    super(props)
  }
  render() {
    return (
      
    )
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
          this.props.onLogin()
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
