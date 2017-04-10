class App extends React.Component {
  constructor(props) {
    super(props)
  }

  componentDidMount() {
  }

  componentWillUnmount() {
  }

  render() {
    return (
      <p>Hello, Universe</p>
    )
  }
};

ReactDOM.render(
  <App />,
  document.getElementById('app')
);
