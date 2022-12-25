// Need to cache all dynamic instances
const instanceCache: { [key: string]: any } = {};

export function Singleton<T>(
  instanceName: string,
  Constructor: new (...params: any[]) => T,
  ...constructorParams: any[]
): T {
  if (typeof instanceCache[instanceName] === 'undefined') {
    // Construct new instance with given params
    instanceCache[instanceName] = new Constructor(...constructorParams);
  }
  return instanceCache[instanceName];
}

export default Singleton;
