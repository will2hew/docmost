import { IWorkspace } from "@/features/workspace/types/workspace.types";

export interface IUser {
  id: string;
  name: string;
  email: string;
  avatarUrl: string;
  timezone: string;
  role: string;
  workspaceId: string;
  fullPageWidth: boolean; // used for update
}

export interface ICurrentUser {
  user: IUser;
  workspace: IWorkspace;
}

export interface IUserSettings {
  preferences: {
    fullPageWidth: boolean;
  };
}
