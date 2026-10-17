<?php

/**
 * Minimal IntegerField parent for the pin UidField.php gadget.
 * setValue / isSet / asInt match OPNsense BaseField on this pin:
 * isSet is getValue() !== '', so "0" stays set (unlike empty("0")).
 */

namespace OPNsense\Base\FieldTypes;

class IntegerField
{
    protected mixed $internalValue = "";

    protected mixed $internalParentModel = null;

    protected mixed $internalParentNode = null;

    public function setValue($value)
    {
        $this->internalValue = (string)$value;
    }

    public function getValue(): string
    {
        return (string)$this->internalValue;
    }

    public function isSet(): bool
    {
        return $this->getValue() !== "";
    }

    public function asInt(): int
    {
        return (int)$this->getValue();
    }

    public function getParentModel(): mixed
    {
        return $this->internalParentModel;
    }

    public function getParentNode(): mixed
    {
        return $this->internalParentNode;
    }

    public function labBind(mixed $model, mixed $node): void
    {
        $this->internalParentModel = $model;
        $this->internalParentNode = $node;
    }

    protected function actionPostLoadingEvent()
    {
    }

    public function getValidators()
    {
        return [];
    }
}
