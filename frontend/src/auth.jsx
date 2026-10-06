import { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { api } from './api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => api.tokens.user);
  const [trust, setTrust] = useState(() => api.tokens.trust);

  const login = useCallback(async (credentials) => {
    const tokens = await api.login(credentials);
    setUser(tokens.user);
    setTrust(tokens.trust_score);
    return tokens;
  }, []);

  const logout = useCallback(async () => {
    await api.logout();
    setUser(null);
    setTrust(0);
  }, []);

  const value = useMemo(
    () => ({
      user,
      trust,
      login,
      logout,
      // Mirrors the API's RequireRole: ADMIN satisfies every check.
      can: (role) => Boolean(user) && (user.role === 'ADMIN' || user.role === role),
    }),
    [user, trust, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used inside <AuthProvider>');
  return context;
}
