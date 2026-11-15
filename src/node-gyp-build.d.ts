declare module "node-gyp-build" {
  function load<T = unknown>(directory: string): T;

  export default load;
}