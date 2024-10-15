import { util } from "../lib/util";

describe("roundUpExact Tests", () => {
  it("Should return the Number", () => {
    expect(util.roundUpExact(0.1 + 0.2)).toBe(0.3);

    expect(util.roundUpExact(0.6 + 0.2)).toBe(0.8);

    expect(util.roundUpExact(0.4 + 0.2)).toBe(0.6);

    expect(util.roundUpExact(0.8 + 0.2)).toBe(1);
  });
});
