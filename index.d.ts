declare module 'egg' {
  interface Application {
    dd: {
      getDept(id: number): Promise<void>;
      getDeptList(parentId?: number, recursion?: boolean): Promise<void>;
      getRoleTree(): Promise<void>
    };
  }
}
