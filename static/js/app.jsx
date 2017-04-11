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

    handleNameChange(username) {
      this.setState({name: username});
    }

    handleEmailChange(address) {
      this.setState({email: address});
    }

    handleSubmit(event) {
      event.preventDefault();
      fetch('/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: this.state.name,
          email: this.state.email,
        })
      })
    }

    render() {
      return (
        <form onSubmit={this.handleSubmit}>
          <div className="form-group">
            <label className="lead" for="name">
              Name:
              <MyInput type="text" id="name" className="form-control" value={this.state.name} onChange={this.handleNameChange} />
            </label>
        </div>
        <div className="form-group">
          <label className="lead" for="email">
            Email:
            <MyInput type="email" id="email" className="form-control" value={this.state.email} onChange={this.handleEmailChange} />
          </label>
        </div>
        <div className="form-group">
          <input type="submit" className="btn btn-lg btn-default" value="Subscribe" />
        </div>
        </form>
      );
    }
};

class MyInput extends React.Component {
  constructor(props) {
    super(props);
    this.handleChange = this.handleChange.bind(this);
  }

  handleChange(e) {
    this.props.onChange(e.target.value);
  }

  render() {
    const value = this.props.value;
    const type = this.props.type;
    return (
      <input type={type} value={value} onChange={this.handleChange} />
    );
  }
}

ReactDOM.render(
  <App />,
  document.getElementById('app')
);
