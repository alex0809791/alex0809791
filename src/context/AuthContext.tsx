import React, { createContext, useContext, useState, useEffect } from 'react';
import { UserProfile, SubscriptionStatus } from '../types';
import {
  getStoredUsers,
  saveStoredUsers,
  getActiveUserId,
  setActiveUserId,
} from '../utils/storage';
import {
  hashPassword,
  generateSalt,
  isWebAuthnSupported,
  registerBiometricPasskey,
  authenticateWithBiometrics,
} from '../utils/crypto';
import { supabase, TRIAL_DAYS, APP_DOMAIN } from '../utils/supabase';

interface AuthContextType {
  user: UserProfile | null;
  loading: boolean;
  isBiometricsAvailable: boolean;
  subscriptionStatus: SubscriptionStatus;
  isRecoveryMode: boolean;
  setIsRecoveryMode: (val: boolean) => void;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  register: (name: string, email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
  updateProfile: (name: string, avatarUrl?: string) => Promise<{ success: boolean; error?: string }>;
  updatePassword: (currentPassword: string, newPassword: string) => Promise<{ success: boolean; error?: string }>;
  registerBiometrics: () => Promise<{ success: boolean; error?: string }>;
  loginWithBiometrics: () => Promise<{ success: boolean; error?: string }>;
  requestPasswordReset: (email: string) => Promise<{ success: boolean; error?: string; message?: string }>;
  markSubscriptionActive: () => void;
  resetTrial: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [isBiometricsAvailable, setIsBiometricsAvailable] = useState<boolean>(false);
  const [isRecoveryMode, setIsRecoveryMode] = useState<boolean>(() => {
    return window.location.hash.includes('access_token') && window.location.hash.includes('type=recovery');
  });

  // Compute subscription and trial status based on user registration
  const computeSubscriptionStatus = (currentUser: UserProfile | null | undefined): SubscriptionStatus => {
    if (!currentUser) {
      return {
        isTrial: false,
        trialDaysTotal: TRIAL_DAYS,
        trialDaysLeft: 0,
        isExpired: false,
        isSubscribed: false,
        accessGranted: false,
        registeredAt: new Date().toISOString(),
      };
    }

    if (currentUser?.isSubscribed) {
      return {
        isTrial: false,
        trialDaysTotal: TRIAL_DAYS,
        trialDaysLeft: 0,
        isExpired: false,
        isSubscribed: true,
        accessGranted: true,
        registeredAt: currentUser?.createdAt || new Date().toISOString(),
      };
    }

    const regDate = currentUser?.createdAt ? new Date(currentUser.createdAt) : new Date();
    const now = new Date();
    const diffMs = now.getTime() - regDate.getTime();
    const daysElapsed = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    const trialDaysLeft = Math.max(0, TRIAL_DAYS - daysElapsed);
    const isExpired = daysElapsed >= TRIAL_DAYS;

    return {
      isTrial: !isExpired,
      trialDaysTotal: TRIAL_DAYS,
      trialDaysLeft,
      isExpired,
      isSubscribed: false,
      accessGranted: !isExpired,
      registeredAt: currentUser?.createdAt || new Date().toISOString(),
    };
  };

  const subscriptionStatus = computeSubscriptionStatus(user);

  useEffect(() => {
    // Check biometrics platform support
    isWebAuthnSupported().then(supported => {
      setIsBiometricsAvailable(supported);
    });

    // Check active session in local storage
    const activeId = getActiveUserId();
    if (activeId) {
      const users = getStoredUsers();
      const current = users.find(u => u.id === activeId);
      if (current) {
        setUser(current);
      } else {
        setActiveUserId(null);
      }
    }

    // Also check if Supabase has an active session (e.g. from password recovery link)
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session?.user && !activeId) {
        const users = getStoredUsers();
        let matched = users.find(u => u.email.toLowerCase() === session.user.email?.toLowerCase());
        if (matched) {
          setUser(matched);
          setActiveUserId(matched.id);
        }
      }
      setLoading(false);
    });

    const { data: authListener } = supabase.auth.onAuthStateChange((event, session) => {
      if (event === 'PASSWORD_RECOVERY') {
        setIsRecoveryMode(true);
      }
      if (event === 'SIGNED_IN' && session?.user) {
        const users = getStoredUsers();
        let matched = users.find(u => u.email.toLowerCase() === session.user.email?.toLowerCase());
        if (matched) {
          setUser(matched);
          setActiveUserId(matched.id);
        }
      }
    });

    return () => {
      authListener?.subscription?.unsubscribe();
    };
  }, []);

  const login = async (email: string, password: string): Promise<{ success: boolean; error?: string }> => {
    const trimmedEmail = email.trim().toLowerCase();
    const users = getStoredUsers();
    const existing = users.find(u => u.email.toLowerCase() === trimmedEmail);

    // 1. Attempt Supabase Auth login
    try {
      const { data: supaData, error: supaError } = await supabase.auth.signInWithPassword({
        email: trimmedEmail,
        password,
      });

      if (!supaError && supaData?.user) {
        // Authenticated with Supabase!
        let activeUser = existing;
        if (!activeUser) {
          // If user exists in Supabase but not yet in local storage on this browser, synthesize local user
          const salt = generateSalt();
          const hash = await hashPassword(password, salt);
          const createdAt = supaData.user.created_at || new Date().toISOString();
          activeUser = {
            id: supaData.user.id || 'usr_' + Date.now().toString(36),
            email: trimmedEmail,
            name: supaData.user.user_metadata?.name || trimmedEmail.split('@')[0],
            passwordHash: hash,
            salt,
            createdAt,
            isSubscribed: false,
          };
          saveStoredUsers([...users, activeUser]);
        }
        setUser(activeUser);
        setActiveUserId(activeUser.id);
        return { success: true };
      }
    } catch (supaErr) {
      console.warn('Supabase sign-in fallback to local verification:', supaErr);
    }

    // 2. Fallback to local storage credentials (guarantees offline/previous accounts work flawlessly)
    if (!existing) {
      return { success: false, error: 'E-mail ou senha incorretos.' };
    }

    const computedHash = await hashPassword(password, existing.salt);
    if (computedHash !== existing.passwordHash) {
      return { success: false, error: 'E-mail ou senha incorretos.' };
    }

    setUser(existing);
    setActiveUserId(existing.id);
    return { success: true };
  };

  const register = async (name: string, email: string, password: string): Promise<{ success: boolean; error?: string }> => {
    const trimmedEmail = email.trim().toLowerCase();
    const trimmedName = name.trim() || trimmedEmail.split('@')[0];

    if (!trimmedEmail || !password) {
      return { success: false, error: 'Preencha todos os campos obrigatórios.' };
    }

    if (password.length < 6) {
      return { success: false, error: 'A senha deve ter no mínimo 6 caracteres.' };
    }

    const users = getStoredUsers();
    const exists = users.some(u => u.email.toLowerCase() === trimmedEmail);
    if (exists) {
      return { success: false, error: 'Já existe uma conta cadastrada com este e-mail.' };
    }

    let supaUserId = '';
    const nowIso = new Date().toISOString();

    // 1. Create user in Supabase
    try {
      const { data: supaData, error: supaError } = await supabase.auth.signUp({
        email: trimmedEmail,
        password,
        options: {
          data: {
            name: trimmedName,
            registered_at: nowIso,
          },
          emailRedirectTo: `${APP_DOMAIN}`,
        },
      });

      if (supaError) {
        // If Supabase reports user already registered
        if (supaError.message.includes('User already registered') || supaError.status === 422) {
          return { success: false, error: 'Já existe uma conta cadastrada com este e-mail no Supabase. Tente entrar ou recupere a senha.' };
        }
        console.warn('Supabase registration error (proceeding with local registration):', supaError.message);
      } else if (supaData?.user) {
        supaUserId = supaData.user.id;
      }
    } catch (supaErr: any) {
      console.warn('Supabase exception:', supaErr);
    }

    // 2. Create user in secure Local Storage (preserves zero-latency, local privacy, fallback)
    const salt = generateSalt();
    const passwordHash = await hashPassword(password, salt);

    const newUser: UserProfile = {
      id: supaUserId || 'usr_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      email: trimmedEmail,
      name: trimmedName,
      passwordHash,
      salt,
      createdAt: nowIso,
      isSubscribed: false,
    };

    const updated = [...users, newUser];
    saveStoredUsers(updated);

    setUser(newUser);
    setActiveUserId(newUser.id);
    return { success: true };
  };

  const logout = async () => {
    try {
      await supabase.auth.signOut();
    } catch (err) {
      console.warn('Supabase signOut error:', err);
    }
    setUser(null);
    setActiveUserId(null);
  };

  const requestPasswordReset = async (email: string): Promise<{ success: boolean; error?: string; message?: string }> => {
    const trimmedEmail = email.trim().toLowerCase();
    if (!trimmedEmail) {
      return { success: false, error: 'Informe seu e-mail cadastrado.' };
    }

    try {
      const { error } = await supabase.auth.resetPasswordForEmail(trimmedEmail, {
        redirectTo: `${APP_DOMAIN}/#reset-password`,
      });

      if (error) {
        return { success: false, error: error.message };
      }

      return {
        success: true,
        message: 'Link de recuperação enviado com sucesso! Verifique sua caixa de entrada e spam.',
      };
    } catch (err: any) {
      return { success: false, error: err.message || 'Erro ao solicitar recuperação de senha.' };
    }
  };

  const markSubscriptionActive = () => {
    if (!user) return;
    const users = getStoredUsers();
    const updatedUsers = users.map(u => {
      if (u.id === user.id) {
        return {
          ...u,
          isSubscribed: true,
          subscriptionExpiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        };
      }
      return u;
    });
    saveStoredUsers(updatedUsers);
    const updated = updatedUsers.find(u => u.id === user.id) || null;
    setUser(updated);
  };

  const resetTrial = () => {
    if (!user) return;
    const users = getStoredUsers();
    const updatedUsers = users.map(u => {
      if (u.id === user.id) {
        return {
          ...u,
          createdAt: new Date().toISOString(),
          isSubscribed: false,
        };
      }
      return u;
    });
    saveStoredUsers(updatedUsers);
    const updated = updatedUsers.find(u => u.id === user.id) || null;
    setUser(updated);
  };

  const updateProfile = async (name: string, avatarUrl?: string): Promise<{ success: boolean; error?: string }> => {
    if (!user) return { success: false, error: 'Usuário não autenticado.' };

    const users = getStoredUsers();
    const updatedUsers = users.map(u => {
      if (u.id === user.id) {
        return {
          ...u,
          name: name.trim(),
          avatarUrl: avatarUrl !== undefined ? avatarUrl : u.avatarUrl,
        };
      }
      return u;
    });

    saveStoredUsers(updatedUsers);
    const updated = updatedUsers.find(u => u.id === user.id) || null;
    setUser(updated);
    return { success: true };
  };

  const updatePassword = async (currentPassword: string, newPassword: string): Promise<{ success: boolean; error?: string }> => {
    if (!user) return { success: false, error: 'Usuário não autenticado.' };
    if (newPassword.length < 6) {
      return { success: false, error: 'A nova senha deve ter no mínimo 6 caracteres.' };
    }

    const currentHash = await hashPassword(currentPassword, user.salt);
    if (currentHash !== user.passwordHash) {
      return { success: false, error: 'A senha atual está incorreta.' };
    }

    const newSalt = generateSalt();
    const newHash = await hashPassword(newPassword, newSalt);

    // Also update on Supabase if connected
    try {
      await supabase.auth.updateUser({ password: newPassword });
    } catch (err) {
      console.warn('Supabase password update notice:', err);
    }

    const users = getStoredUsers();
    const updatedUsers = users.map(u => {
      if (u.id === user.id) {
        return {
          ...u,
          passwordHash: newHash,
          salt: newSalt,
        };
      }
      return u;
    });

    saveStoredUsers(updatedUsers);
    const updated = updatedUsers.find(u => u.id === user.id) || null;
    setUser(updated);
    return { success: true };
  };

  const registerBiometrics = async (): Promise<{ success: boolean; error?: string }> => {
    if (!user) return { success: false, error: 'Usuário não autenticado.' };
    if (!isBiometricsAvailable) {
      return { success: false, error: 'Biometria/Passkey não é suportada neste navegador ou dispositivo.' };
    }

    try {
      const res = await registerBiometricPasskey(user.id, user.email, user.name);
      if (res.success && res.credentialId) {
        const users = getStoredUsers();
        const updatedUsers = users.map(u => {
          if (u.id === user.id) {
            return {
              ...u,
              hasBiometrics: true,
              biometricCredentialId: res.credentialId,
            };
          }
          return u;
        });
        saveStoredUsers(updatedUsers);
        const updated = updatedUsers.find(u => u.id === user.id) || null;
        setUser(updated);
        return { success: true };
      }
      return { success: false, error: 'Falha ao registrar biometria.' };
    } catch (err: any) {
      return { success: false, error: err.message || 'Erro ao configurar biometria.' };
    }
  };

  const loginWithBiometrics = async (): Promise<{ success: boolean; error?: string }> => {
    if (!isBiometricsAvailable) {
      return { success: false, error: 'Biometria não suportada neste dispositivo.' };
    }

    try {
      const users = getStoredUsers();
      const bioUsers = users.filter(u => u.hasBiometrics);
      if (bioUsers.length === 0) {
        return { success: false, error: 'Nenhuma conta configurada com biometria neste navegador.' };
      }

      const targetCredentialId = bioUsers.length === 1 ? bioUsers[0].biometricCredentialId : undefined;
      const success = await authenticateWithBiometrics(targetCredentialId);
      if (success) {
        const authenticatedUser = bioUsers[0];
        setUser(authenticatedUser);
        setActiveUserId(authenticatedUser.id);
        return { success: true };
      }
      return { success: false, error: 'Autenticação biométrica não concluída.' };
    } catch (err: any) {
      return { success: false, error: err.message || 'Erro na autenticação biométrica.' };
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        isBiometricsAvailable,
        subscriptionStatus,
        isRecoveryMode,
        setIsRecoveryMode,
        login,
        register,
        logout,
        updateProfile,
        updatePassword,
        registerBiometrics,
        loginWithBiometrics,
        requestPasswordReset,
        markSubscriptionActive,
        resetTrial,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth deve ser usado dentro de AuthProvider');
  }
  return context;
};
