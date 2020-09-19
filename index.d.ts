declare module 'egg' {
  interface Application {
    dd: {
      getDept(id: number | string): Promise<void>;
      getDeptList(parentId?: number | string, recursion?: boolean): Promise<void>;
      getRoleTree(): Promise<void>;
      getDeptUserList(departmentId: number | string): Promise<void>;
    };
  }
}
