declare module 'egg' {
  interface Application {
    dd: {
      getDept(id): Promise<void>;
      getDeptList(parentId?: number, recursion?: boolean): Promise<void>;
    };
  }
}
