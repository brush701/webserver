class App extends React.Component {
  constructor(props) {
      super(props);
      this.state = {name: '',
                    email: '',
                    subscribed: false};

      this.handleNameChange = this.handleNameChange.bind(this);
      this.handleEmailChange = this.handleEmailChange.bind(this);
      this.handleSubmit = this.handleSubmit.bind(this);
    }

    handleNameChange(e) {
      this.setState({name: e.target.value});
    }

    handleEmailChange(e) {
      this.setState({email: e.target.value});
    }

    handleSubmit(event) {
      event.preventDefault();
      var self = this
      fetch('/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: this.state.name,
          email: this.state.email,
        })
      }).then(function(response){
        if(response.ok){
          self.setState({subscribed: true})
        }
      })
    }

    render() {
      if(this.state.subscribed) {
        return(<h1>Thank you for subscribing!</h1>)
      } else {
        return (
          <form onSubmit={this.handleSubmit}>
            <div className="form-group">
              <label className="lead" for="name">
                Name:
              </label>
                <input type="text" id="name" className="form-control" value={this.state.name} onChange={this.handleNameChange} />
            </div>
          <div className="form-group">
            <label className="lead" for="email">
              Email:
            </label>
            <input type="email" id="email" className="form-control" value={this.state.email} onChange={this.handleEmailChange} />
            </div>
          <div className="form-group">
            <input type="submit" className="btn btn-lg btn-default" value="Subscribe" />
          </div>
          </form>
        );
      }
    }
};


ReactDOM.render(
  <App />,
  document.getElementById('app')
);
