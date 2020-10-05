declare module 'egg' {
  interface Application {
    dd: {
      getDept(id: number | string): Promise<void>;
      getDeptList(parentId?: number | string, recursion?: boolean): Promise<void>;
      getRoleTree(): Promise<void>;
      getDeptUserList(departmentId: number | string): Promise<void>;
      getRoleUserList(roleId: number | string): Promise<void>;
      getUserId(code: string): Promise<void>;
      getUrl(): Promise<void>;
      setUrl(tags: Array<string>, url: string, type?: string): Promise<void>;
      delUrl(): Promise<void>;
      decrypt(text: string): string;
      callback(text?: string): object;
      getAttCols(): Promise<void>;
      getColsVal(ddUserId: string, colIds: string, from: string, to: string): Promise<void>;
      getLeaveVal(ddUserId: string, leaveNames: string, from: string, to: string): Promise<void>;
    };
  }
}
