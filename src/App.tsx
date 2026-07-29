function App() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-background">
      <div className="text-center">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">
          Password Manager
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Secure, encrypted secrets — synced to your own S3-compatible storage.
        </p>
      </div>
    </main>
  );
}

export default App;
